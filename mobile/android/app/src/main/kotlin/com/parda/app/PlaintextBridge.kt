package com.parda.app

/**
 * JVM half of the plaintext-buffer bridge (Sub-Phase 4.5C) — mirrors
 * `MeshBridge`'s `object` + `init { System.loadLibrary(...) }` +
 * `external fun` shape, loading the same `parda_mobile_bridge` native
 * library (see `mobile-bridge/src/lib.rs`'s module docs on why a second
 * `System.loadLibrary` target wasn't introduced for this).
 *
 * Unlike `MeshBridge`'s methods, every function here is a plain
 * synchronous native call — there is no async BLE-callback shape to
 * bridge, so there are no `nativeOnXxxResult` callbacks for Rust to
 * call back into; Kotlin calls in, Rust returns directly.
 *
 * `SignalPlugin.kt`'s `handleDecryptMessage` is the only caller: instead
 * of handing the JVM `ByteArray` decrypted by libsignal-android straight
 * across the Flutter MethodChannel (today's behavior for every *other*
 * plugin method), it hands it to [nativePlaintextNew] and returns only
 * the resulting opaque handle to Dart. See
 * `docs/phase4.5c-dart-plaintext-design.md`.
 */
object PlaintextBridge {
    init {
        System.loadLibrary("parda_mobile_bridge")
    }

    /** Takes ownership of a copy of `bytes`; returns `0` on failure. */
    @JvmStatic
    external fun nativePlaintextNew(bytes: ByteArray): Long

    /** `0` if `handle` is `0` or already released. */
    @JvmStatic
    external fun nativePlaintextLen(handle: Long): Long

    /** `null` if `handle` is `0` or already released. */
    @JvmStatic
    external fun nativePlaintextCopyInto(handle: Long): ByteArray?

    /** No-op if `handle` is `0` or already released. */
    @JvmStatic
    external fun nativePlaintextRelease(handle: Long)
}
