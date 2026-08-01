package com.parda.app

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

/**
 * Flutter-facing side of the plaintext-buffer bridge (Sub-Phase 4.5C).
 * Mirrors `MeshPlugin.kt`'s shape (thin `FlutterPlugin` forwarding to a
 * native-backed object) — here forwarding to [PlaintextBridge] instead
 * of [MeshBridge]. Separate plugin/channel from `SignalPlugin`
 * (`com.parda.app/plaintext` vs `com.parda.app/signal`) because a
 * handle, once returned by `decryptMessage`, is read/released
 * independently of any further Signal-protocol operation — keeping the
 * two channels apart matches the existing signal/mesh responsibility
 * split, not a new pattern.
 *
 * ## Method channel: `com.parda.app/plaintext`
 *
 * - `copyInto(handle: Long)` → `ByteArray?`
 * - `release(handle: Long)` → `void`
 */
class PlaintextPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel

    companion object {
        const val CHANNEL = "com.parda.app/plaintext"
    }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, CHANNEL)
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        val handle = (call.argument<Number>("handle") ?: 0).toLong()
        when (call.method) {
            "copyInto" -> result.success(PlaintextBridge.nativePlaintextCopyInto(handle))
            "release" -> {
                PlaintextBridge.nativePlaintextRelease(handle)
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }
}
