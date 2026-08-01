//! PARDA Rust↔JNI bridge for Android mesh radio (Sub-Phase 4.5B).
//!
//! ## The premise this corrects
//!
//! The Sub-Phase 4.5B brief describes this as "following the same
//! Rust-to-native-platform bridging pattern already established by
//! `SignalPlugin.kt`." That premise doesn't hold: reading
//! `mobile/android/app/src/main/kotlin/com/parda/app/SignalPlugin.kt`
//! shows it bridges Dart → Kotlin → `org.signal.libsignal.protocol.*`
//! (Signal's own JVM/Android port of libsignal) — it never touches the
//! Rust `protocol` crate at all. There is no existing Rust↔JNI bridge in
//! this codebase to extend; this crate is a new one, built from scratch.
//! Stated here rather than left for a reader to assume otherwise.
//!
//! ## Why a purpose-built bridge, not an existing crate
//!
//! Checked before writing this (not assumed): `blew`/`ble-peripheral-rust`
//! both claim some cross-platform Android BLE peripheral support via
//! Kotlin/JNI glue. Neither was adopted here — their exact API surface,
//! maturity, and compatibility with `cargo-ndk`'s build flow were
//! unverified within this session's time budget, and adopting an
//! unfamiliar crate mid-task under time pressure risks trading a small,
//! reasoned, purpose-built bridge (easy to audit end-to-end) for a
//! larger unaudited dependency — the same category of tradeoff Sub-Phase
//! 4B already weighed when it chose `bp7` (wire format only) over
//! embedding the `dtn7` daemon crate. `jni` (the `jni-rs` project) *is*
//! used directly — that's the audited primitive; the callback-bridging
//! logic built on top of it is this crate's own, minimal, and reviewable
//! in full.
//!
//! ## Design: bridging JVM callbacks into `async`/`await`
//!
//! Android's BLE APIs (`BluetoothLeAdvertiser`, `BluetoothLeScanner`,
//! `BluetoothGattServer`) are callback-driven, not blocking — a Kotlin
//! call like `startAdvertising(...)` returns immediately, and the result
//! arrives later via `AdvertiseCallback.onStartSuccess`/`onStartFailure`,
//! invoked on some JVM thread. [`radio::AndroidMeshRadio`]'s `async fn`
//! methods (implementing `parda_mesh::radio::MeshRadio`) bridge this via
//! [`pending`]: each call registers a channel under a fresh request ID,
//! calls into Kotlin (`ffi::call_into_kotlin`) passing that ID, and
//! `.await`s the channel. The JNI-exported native callback entry points
//! ([`jni_exports`]) — which Kotlin calls when its own BLE callback
//! fires — look up the ID and resolve (or push to, for the streaming
//! `scan` case) the matching channel. Neither side blocks the other's
//! thread; the bridge is purely a lookup table plus channels.
//!
//! ## What this crate does NOT prove
//!
//! This crate compiles (via `cargo-ndk`, cross-compiled for
//! `x86_64-linux-android`/`aarch64-linux-android`) and links into a real
//! Gradle-built APK — that much is a genuine, verified claim.
//! **Whether the resulting mesh radio actually advertises/scans/connects
//! over real or emulated (rootcanal) Bluetooth is a separate, weaker
//! claim, reported honestly in `docs/THREAT_MODEL.md` and the README
//! exactly as far as this session's testing actually got — not rounded
//! up.**
//!
//! ## `plaintext_exports` (Sub-Phase 4.5C)
//!
//! A second, unrelated bridging surface added later, reusing this same
//! crate/cdylib rather than a new one only because a second
//! `System.loadLibrary` target would add build/packaging surface for no
//! benefit — `SignalPlugin.kt` and `MeshBridge.kt` are independent
//! JVM-side callers of the same native library. Unlike the async
//! request/callback pattern above, [`plaintext_exports`]'s calls are
//! plain synchronous FFI (no waiting on a Kotlin callback) — but it
//! *does* reuse [`pending::next_id`] for ID generation, and reuses the
//! same "opaque `i64` ID into a registry map, never a raw pointer
//! round-tripped through the JVM" shape for the same reason
//! `pending`'s registries exist: an ID that outlives its backing value
//! just misses the map, instead of a freed `Box` being dereferenced.
//! See `docs/phase4.5c-dart-plaintext-design.md`.

pub mod pending;
pub mod radio;

mod ffi;
mod jni_exports;
mod lifecycle;
mod plaintext_exports;

pub use radio::AndroidMeshRadio;

use jni::JavaVM;
use std::{ffi::c_void, os::raw::c_int, sync::OnceLock};

static JVM: OnceLock<JavaVM> = OnceLock::new();

/// Called automatically by the JVM when it loads this library
/// (`System.loadLibrary("parda_mobile_bridge")`, `MeshBridge.kt`).
/// Caches the `JavaVM` handle so [`ffi::with_env`] can attach from
/// whichever thread a `MeshRadio` `async fn` happens to be polled on —
/// Rust's tokio worker threads are never JVM-attached by default.
///
/// # Safety
/// Required JNI entry-point signature; the JVM calls this, not Rust code.
#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn JNI_OnLoad(vm: JavaVM, _reserved: *mut c_void) -> c_int {
    let _ = JVM.set(vm);
    tracing_subscriber::fmt::try_init().ok();
    tracing::info!("parda-mobile-bridge loaded");
    jni::sys::JNI_VERSION_1_6
}

pub(crate) fn jvm() -> &'static JavaVM {
    JVM.get().expect(
        "JNI_OnLoad has not run yet — this native library must be loaded via \
         System.loadLibrary before any bridged call, never called from a pure-Rust test \
         context (see mobile-bridge's own unit tests, which exercise `pending` directly \
         instead)",
    )
}
