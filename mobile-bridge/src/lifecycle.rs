//! Start/stop entry points for the mesh node, exposed to
//! `MeshPlugin.kt`'s `startMesh`/`stopMesh` Dart-facing methods via JNI.
//! Owns the actual `parda_mesh::transport::MeshNode` — everything below
//! is just wiring `AndroidMeshRadio` into the same
//! `MeshRelayAgent`/`spawn_sync_loop`/`spawn_accept_loop` machinery
//! Sub-Phase 4B already built and tested against `SimulatedMeshRadio`.
//! No new mesh logic lives here.

use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use jni::{objects::JClass, JNIEnv};
use parda_mesh::{radio::MeshRadio, relay::MeshRelayAgent, transport::MeshNode};
use tokio::runtime::Runtime;

use crate::AndroidMeshRadio;

struct RunningMesh {
    _runtime: Runtime,
    _sync_handle: tokio::task::JoinHandle<()>,
    _accept_handle: tokio::task::JoinHandle<()>,
}

static RUNNING: OnceLock<std::sync::Mutex<Option<RunningMesh>>> = OnceLock::new();

fn running_slot() -> &'static std::sync::Mutex<Option<RunningMesh>> {
    RUNNING.get_or_init(|| std::sync::Mutex::new(None))
}

/// Sync-loop duty cycle. See `mesh/tests/battery_cost_tests.rs`
/// (Sub-Phase 4D) for what this trades off — a real device should tune
/// this, not just inherit the test suite's illustrative default.
const SYNC_INTERVAL: Duration = Duration::from_secs(30);

/// # Safety
/// Standard JNI native-method entry point; called only by the JVM.
#[no_mangle]
pub extern "system" fn Java_com_parda_app_MeshPlugin_nativeStartMesh<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) {
    let mut guard = running_slot().lock().unwrap();
    if guard.is_some() {
        tracing::debug!("mesh already running — nativeStartMesh is a no-op");
        return;
    }
    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::warn!(error = %e, "failed to start tokio runtime for mesh node");
            return;
        }
    };
    let radio: Arc<dyn MeshRadio> = Arc::new(AndroidMeshRadio::new());
    let relay = Arc::new(MeshRelayAgent::new(Default::default()));
    let node = MeshNode::new(radio, relay);

    // `spawn_sync_loop`/`spawn_accept_loop` (`mesh/src/transport.rs`,
    // Sub-Phase 4B) call `tokio::spawn` internally and need a runtime
    // context on the current thread to do so — `enter()` provides that
    // without driving the runtime's event loop here (this thread is a
    // JNI call from the JVM, not the runtime's own worker pool; the
    // already-running worker threads `Runtime::new()` created do the
    // actual polling).
    let _guard = runtime.enter();
    let sync_handle = Arc::clone(&node).spawn_sync_loop(SYNC_INTERVAL);
    let accept_handle = node.spawn_accept_loop();

    *guard = Some(RunningMesh {
        _runtime: runtime,
        _sync_handle: sync_handle,
        _accept_handle: accept_handle,
    });
    tracing::info!("mesh node started");
}

/// # Safety
/// Standard JNI native-method entry point; called only by the JVM.
#[no_mangle]
pub extern "system" fn Java_com_parda_app_MeshPlugin_nativeStopMesh<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) {
    if let Some(running) = running_slot().lock().unwrap().take() {
        running._sync_handle.abort();
        running._accept_handle.abort();
        tracing::info!("mesh node stopped");
    }
}
