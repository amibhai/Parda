//! JNI entry points bridging Kotlin's `PlaintextBridge.kt` to
//! `parda_protocol::plaintext_ffi::PlaintextHandle` (Sub-Phase 4.5C —
//! see `docs/phase4.5c-dart-plaintext-design.md`).
//!
//! Unlike `jni_exports.rs`'s async callback pattern (Kotlin reports
//! back whenever its own async BLE work finishes, resolved through
//! [`crate::pending`]), every call here is a plain synchronous FFI
//! call: `PlaintextHandle::new`/`len`/`copy_into`/`release` are all
//! synchronous, so Kotlin calls in and gets a direct return value.
//!
//! ## Why an ID registry, not a raw boxed pointer
//!
//! An earlier version of this module round-tripped `Box::into_raw`/
//! `Box::from_raw` directly as the `jlong` handle — the same shape
//! `radio.rs` uses for link handles. That shape is only safe if callers
//! never touch a handle again after releasing it. For plaintext
//! specifically, that's not a contract this crate can just declare and
//! trust: `SessionService.dart`'s bulk release-on-backgrounding path
//! (see `docs/phase4.5c-dart-plaintext-design.md` and
//! `mobile/lib/services/session_service.dart`) and a widget's own
//! `dispose()` are two independent call sites that could plausibly race
//! or double-fire against the same handle in a way a raw pointer cannot
//! survive — dereferencing a freed `Box` is undefined behavior, not a
//! safe "already gone" signal, no matter how carefully the doc comments
//! word the precondition. Found while writing this module's own
//! instrumented test (`PlaintextForensicRecoveryTest.kt`'s
//! post-release-access case), which would otherwise have exercised UB.
//!
//! An `i64` ID into a registry map — the exact pattern
//! [`crate::pending`] already uses for request/stream IDs — fixes this
//! structurally: an already-released ID is simply absent from the map,
//! so every operation is a safe lookup that fails closed
//! (`len` → `0`, `copy_into` → `null`) instead of touching freed memory.

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use jni::{
    objects::JClass,
    sys::{jbyteArray, jlong},
    JNIEnv,
};
use parda_protocol::plaintext_ffi::PlaintextHandle;
use zeroize::Zeroize;

use crate::{ffi::jbytearray_to_vec, pending};

fn registry() -> &'static Mutex<HashMap<i64, PlaintextHandle>> {
    static REGISTRY: OnceLock<Mutex<HashMap<i64, PlaintextHandle>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// `PlaintextBridge.nativePlaintextNew(bytes: ByteArray): Long`.
///
/// # Safety
/// Standard JNI native-method entry point; called only by the JVM.
/// Returns `0` (never an ID [`pending::next_id`] hands out — IDs start
/// at 1) if `bytes` can't be read.
#[no_mangle]
pub extern "system" fn Java_com_parda_app_PlaintextBridge_nativePlaintextNew<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    bytes: jbyteArray,
) -> jlong {
    let Ok(vec) = jbytearray_to_vec(&mut env, bytes) else {
        return 0;
    };
    let id = pending::next_id();
    registry().lock().unwrap().insert(id, PlaintextHandle::new(vec));
    id
}

/// `PlaintextBridge.nativePlaintextLen(handle: Long): Long`.
/// `0` if `handle` is unknown or already released — a safe map lookup,
/// not a use-after-free.
#[no_mangle]
pub extern "system" fn Java_com_parda_app_PlaintextBridge_nativePlaintextLen<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jlong {
    registry()
        .lock()
        .unwrap()
        .get(&handle)
        .map(|h| h.len() as jlong)
        .unwrap_or(0)
}

/// `PlaintextBridge.nativePlaintextCopyInto(handle: Long): ByteArray?`.
/// `null` if `handle` is unknown or already released.
#[no_mangle]
pub extern "system" fn Java_com_parda_app_PlaintextBridge_nativePlaintextCopyInto<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jbyteArray {
    let len = match registry().lock().unwrap().get(&handle) {
        Some(h) => h.len(),
        None => return std::ptr::null_mut(),
    };
    let mut buf = vec![0u8; len];
    // Re-lock rather than hold the registry lock across the JVM call
    // below (`byte_array_from_slice` can call back into the JVM
    // allocator) — a short second lookup is cheap and avoids holding a
    // std Mutex across a JNI call.
    let copied = registry()
        .lock()
        .unwrap()
        .get(&handle)
        .map(|h| h.copy_into(&mut buf))
        .unwrap_or(false);
    if !copied {
        return std::ptr::null_mut();
    }
    let out = env.byte_array_from_slice(&buf);
    // Zero this function's own transient copy immediately once it's
    // been handed to the JVM (which has its own copy by the time
    // `byte_array_from_slice` returns) — the same "don't leave a
    // redundant unmanaged copy for GC to eventually get to" discipline
    // `SignalPlugin.kt`'s `finally` blocks already apply on the Kotlin
    // side of this same boundary.
    buf.zeroize();
    out.map(|arr| arr.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// `PlaintextBridge.nativePlaintextRelease(handle: Long)`. No-op if
/// `handle` is unknown or already released — idempotent, matching
/// [`PlaintextHandle::release`]'s own idempotence.
#[no_mangle]
pub extern "system" fn Java_com_parda_app_PlaintextBridge_nativePlaintextRelease<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if let Some(h) = registry().lock().unwrap().remove(&handle) {
        h.release();
    }
}
