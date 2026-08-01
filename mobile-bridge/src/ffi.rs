//! Low-level JNI attach/call helpers. Everything here is a thin,
//! directly-reviewable wrapper around the `jni` crate — no unsafe beyond
//! what calling into the JVM inherently requires.

use jni::{
    objects::{JClass, JObject, JValue},
    sys::jbyteArray,
    AttachGuard, JNIEnv,
};

use crate::jvm;

const MESH_BRIDGE_CLASS: &str = "com/parda/app/MeshBridge";

/// Attach the calling thread to the JVM (tokio worker threads aren't
/// attached by default — see crate root docs) and run `f` with the
/// resulting `JNIEnv`. The guard detaches automatically on drop.
pub fn with_env<R>(f: impl FnOnce(&mut JNIEnv) -> jni::errors::Result<R>) -> jni::errors::Result<R> {
    let mut guard: AttachGuard = jvm().attach_current_thread()?;
    f(&mut guard)
}

fn mesh_bridge_class<'a>(env: &mut JNIEnv<'a>) -> jni::errors::Result<JClass<'a>> {
    env.find_class(MESH_BRIDGE_CLASS)
}

fn to_jbytes<'a>(env: &mut JNIEnv<'a>, bytes: &[u8]) -> jni::errors::Result<JObject<'a>> {
    let arr = env.byte_array_from_slice(bytes)?;
    Ok(JObject::from(arr))
}

/// `MeshBridge.startAdvertise(requestId: Long, token: ByteArray)`.
pub fn start_advertise(request_id: i64, token: &[u8]) -> jni::errors::Result<()> {
    with_env(|env| {
        let class = mesh_bridge_class(env)?;
        let token_bytes = to_jbytes(env, token)?;
        env.call_static_method(
            class,
            "startAdvertise",
            "(J[B)V",
            &[JValue::Long(request_id), JValue::Object(&token_bytes)],
        )?;
        Ok(())
    })
}

/// `MeshBridge.startScan(streamId: Long)`.
pub fn start_scan(stream_id: i64) -> jni::errors::Result<()> {
    with_env(|env| {
        let class = mesh_bridge_class(env)?;
        env.call_static_method(class, "startScan", "(J)V", &[JValue::Long(stream_id)])?;
        Ok(())
    })
}

/// `MeshBridge.stopScan(streamId: Long)`.
pub fn stop_scan(stream_id: i64) -> jni::errors::Result<()> {
    with_env(|env| {
        let class = mesh_bridge_class(env)?;
        env.call_static_method(class, "stopScan", "(J)V", &[JValue::Long(stream_id)])?;
        Ok(())
    })
}

/// `MeshBridge.connect(requestId: Long, peerHandle: ByteArray)`.
pub fn connect(request_id: i64, peer_handle: &[u8]) -> jni::errors::Result<()> {
    with_env(|env| {
        let class = mesh_bridge_class(env)?;
        let handle_bytes = to_jbytes(env, peer_handle)?;
        env.call_static_method(
            class,
            "connect",
            "(J[B)V",
            &[JValue::Long(request_id), JValue::Object(&handle_bytes)],
        )?;
        Ok(())
    })
}

/// `MeshBridge.accept(requestId: Long)`.
pub fn accept(request_id: i64) -> jni::errors::Result<()> {
    with_env(|env| {
        let class = mesh_bridge_class(env)?;
        env.call_static_method(class, "accept", "(J)V", &[JValue::Long(request_id)])?;
        Ok(())
    })
}

/// `MeshBridge.send(requestId: Long, linkHandle: Long, bytes: ByteArray)`.
pub fn link_send(request_id: i64, link_handle: i64, bytes: &[u8]) -> jni::errors::Result<()> {
    with_env(|env| {
        let class = mesh_bridge_class(env)?;
        let payload = to_jbytes(env, bytes)?;
        env.call_static_method(
            class,
            "send",
            "(JJ[B)V",
            &[
                JValue::Long(request_id),
                JValue::Long(link_handle),
                JValue::Object(&payload),
            ],
        )?;
        Ok(())
    })
}

/// `MeshBridge.recv(requestId: Long, linkHandle: Long)`.
pub fn link_recv(request_id: i64, link_handle: i64) -> jni::errors::Result<()> {
    with_env(|env| {
        let class = mesh_bridge_class(env)?;
        env.call_static_method(
            class,
            "recv",
            "(JJ)V",
            &[JValue::Long(request_id), JValue::Long(link_handle)],
        )?;
        Ok(())
    })
}

/// Convert a JNI `jbyteArray` (as received in a native callback) to an
/// owned `Vec<u8>`. Used by [`crate::jni_exports`].
pub fn jbytearray_to_vec(env: &mut JNIEnv, arr: jbyteArray) -> jni::errors::Result<Vec<u8>> {
    // SAFETY: `arr` is a valid local ref handed to us by the JVM for the
    // duration of this native call — the standard, documented shape of
    // a JNI callback argument.
    let arr = unsafe { jni::objects::JByteArray::from_raw(arr) };
    env.convert_byte_array(&arr)
}
