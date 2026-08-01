//! Native callback entry points — `MeshBridge.kt`'s `external fun`
//! declarations resolve to these. Each one's only job is: decode the
//! JNI arguments, then hand the result to [`crate::pending`] to resolve
//! (or push to) whatever Rust future/stream is waiting under the given
//! request/stream ID. No BLE logic lives here — that's entirely on the
//! Kotlin side (`MeshBridge.kt`); this file is purely the JVM→Rust half
//! of the bridge described in the crate root docs.

use jni::{
    objects::{JClass, JString},
    sys::{jboolean, jbyteArray, jlong},
    JNIEnv,
};

use crate::{
    ffi::jbytearray_to_vec,
    pending::{self, OneshotResult, ScanResultBytes},
};

fn jstring_to_option(env: &mut JNIEnv, s: JString) -> Option<String> {
    if s.is_null() {
        return None;
    }
    env.get_string(&s).ok().map(|s| s.into())
}

/// # Safety
/// Standard JNI native-method entry point; called only by the JVM.
#[no_mangle]
pub extern "system" fn Java_com_parda_app_MeshBridge_nativeOnAdvertiseResult<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    request_id: jlong,
    success: jboolean,
    error: JString<'local>,
) {
    let result = if success != 0 {
        OneshotResult::Empty
    } else {
        let message = jstring_to_option(&mut env, error).unwrap_or_else(|| "advertise failed (no message)".to_string());
        OneshotResult::Error(message)
    };
    pending::resolve_oneshot(request_id, result);
}

/// # Safety
/// Standard JNI native-method entry point; called only by the JVM.
#[no_mangle]
pub extern "system" fn Java_com_parda_app_MeshBridge_nativeOnScanResult<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    stream_id: jlong,
    peer_handle: jbyteArray,
    token: jbyteArray,
) {
    let Ok(peer_handle) = jbytearray_to_vec(&mut env, peer_handle) else { return };
    let Ok(token) = jbytearray_to_vec(&mut env, token) else { return };
    pending::push_stream(stream_id, ScanResultBytes { peer_handle, token });
}

/// # Safety
/// Standard JNI native-method entry point; called only by the JVM.
#[no_mangle]
pub extern "system" fn Java_com_parda_app_MeshBridge_nativeOnConnectResult<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    request_id: jlong,
    link_handle: jlong,
    error: JString<'local>,
) {
    let result = match jstring_to_option(&mut env, error) {
        Some(message) => OneshotResult::Error(message),
        None => OneshotResult::Bytes(link_handle.to_be_bytes().to_vec()),
    };
    pending::resolve_oneshot(request_id, result);
}

/// # Safety
/// Standard JNI native-method entry point; called only by the JVM.
#[no_mangle]
pub extern "system" fn Java_com_parda_app_MeshBridge_nativeOnAcceptResult<'local>(
    env: JNIEnv<'local>,
    class: JClass<'local>,
    request_id: jlong,
    link_handle: jlong,
    error: JString<'local>,
) {
    // Identical shape to a connect result — accept also yields a link
    // handle or an error, nothing more.
    Java_com_parda_app_MeshBridge_nativeOnConnectResult(env, class, request_id, link_handle, error);
}

/// # Safety
/// Standard JNI native-method entry point; called only by the JVM.
#[no_mangle]
pub extern "system" fn Java_com_parda_app_MeshBridge_nativeOnSendResult<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    request_id: jlong,
    error: JString<'local>,
) {
    let result = match jstring_to_option(&mut env, error) {
        Some(message) => OneshotResult::Error(message),
        None => OneshotResult::Empty,
    };
    pending::resolve_oneshot(request_id, result);
}

/// # Safety
/// Standard JNI native-method entry point; called only by the JVM.
#[no_mangle]
pub extern "system" fn Java_com_parda_app_MeshBridge_nativeOnRecvResult<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    request_id: jlong,
    bytes: jbyteArray,
    error: JString<'local>,
) {
    let result = match jstring_to_option(&mut env, error) {
        Some(message) => OneshotResult::Error(message),
        None => match jbytearray_to_vec(&mut env, bytes) {
            Ok(data) => OneshotResult::Bytes(data),
            Err(e) => OneshotResult::Error(format!("failed to read recv bytes: {e}")),
        },
    };
    pending::resolve_oneshot(request_id, result);
}
