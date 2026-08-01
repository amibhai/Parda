package com.parda.app

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

/**
 * PARDA offline-mesh plugin for Android (Sub-Phase 4.5B).
 *
 * Bridges Flutter MethodChannel calls to the Rust `mobile-bridge` cdylib
 * (`AndroidMeshRadio`, implementing `parda_mesh::radio::MeshRadio` —
 * see `mobile-bridge/src/lib.rs`). The actual BLE advertise/scan/GATT
 * calls the Rust side drives via JNI live in [MeshBridge], not here —
 * this class is purely the Dart-facing start/stop surface, mirroring
 * `SignalPlugin`'s shape for a different responsibility (matching the
 * existing `mesh`/`protocol` Rust crate split).
 *
 * ## Method channel: `com.parda.app/mesh`
 *
 * - `startMesh() -> void` — starts advertising/scanning/relaying
 *   (`parda_mesh::transport::MeshNode`'s sync + accept loops, driven
 *   from Rust — see `mobile-bridge/src/lifecycle.rs`).
 * - `stopMesh() -> void` — stops both loops.
 */
class MeshPlugin : FlutterPlugin, MethodCallHandler {

    private lateinit var channel: MethodChannel

    companion object {
        const val CHANNEL = "com.parda.app/mesh"

        @JvmStatic
        external fun nativeStartMesh()
        @JvmStatic
        external fun nativeStopMesh()

        init {
            System.loadLibrary("parda_mobile_bridge")
        }
    }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, CHANNEL)
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "startMesh" -> {
                nativeStartMesh()
                result.success(null)
            }
            "stopMesh" -> {
                nativeStopMesh()
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }
}
