package com.parda.app

import android.Manifest
import android.app.Activity
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry

/**
 * PARDA offline-mesh plugin for Android (Sub-Phase 4.5B).
 *
 * Bridges Flutter MethodChannel calls to the Rust `mobile-bridge` cdylib
 * (`AndroidMeshRadio`, implementing `parda_mesh::radio::MeshRadio`).
 * The actual BLE advertise/scan/GATT calls live in [MeshBridge]; this
 * class is the Dart-facing surface plus the runtime-permission flow.
 *
 * ## Why the permission flow lives here
 *
 * Android 12+ (API 31+) requires `BLUETOOTH_ADVERTISE`/`BLUETOOTH_SCAN`/
 * `BLUETOOTH_CONNECT` to be granted *at runtime*, not merely declared in
 * the manifest. Declaring them (Sub-Phase 4.5B) without ever requesting
 * them meant every BLE call would fail with a `SecurityException` on a
 * real device — which is exactly why mesh mode was previously
 * unreachable from the app. Requesting them needs an `Activity`, hence
 * [ActivityAware].
 *
 * ## Method channel: `com.parda.app/mesh`
 *
 * | Method | Returns |
 * |--------|---------|
 * | `hasPermissions` | `Boolean` |
 * | `requestPermissions` | `Boolean` — the user's decision, awaited |
 * | `isBluetoothEnabled` | `Boolean` |
 * | `startMesh` | `Boolean` — `false` if blocked by permissions/adapter |
 * | `stopMesh` | `void` |
 * | `isRunning` | `Boolean` |
 */
class MeshPlugin : FlutterPlugin, MethodCallHandler, ActivityAware,
    PluginRegistry.RequestPermissionsResultListener {

    private lateinit var channel: MethodChannel
    private lateinit var appContext: Context
    private var activity: Activity? = null
    private var pendingPermissionResult: Result? = null
    private var running = false

    companion object {
        const val CHANNEL = "com.parda.app/mesh"
        private const val PERMISSION_REQUEST_CODE = 4501

        @JvmStatic
        external fun nativeStartMesh()

        @JvmStatic
        external fun nativeStopMesh()

        init {
            System.loadLibrary("parda_mobile_bridge")
        }

        /**
         * The runtime permissions mesh mode needs.
         *
         * Below API 31 the modern trio does not exist; the legacy
         * equivalent gates BLE scanning behind *location* permission,
         * which is why the manifest declares `neverForLocation` on the
         * modern one — this app derives no location from scan results,
         * only the opaque `AdvertToken` payload.
         */
        fun requiredPermissions(): Array<String> =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                arrayOf(
                    Manifest.permission.BLUETOOTH_ADVERTISE,
                    Manifest.permission.BLUETOOTH_SCAN,
                    Manifest.permission.BLUETOOTH_CONNECT,
                )
            } else {
                arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
            }
    }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        appContext = binding.applicationContext
        channel = MethodChannel(binding.binaryMessenger, CHANNEL)
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
        binding.addRequestPermissionsResultListener(this)
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity
        binding.addRequestPermissionsResultListener(this)
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "hasPermissions" -> result.success(hasPermissions())
            "requestPermissions" -> requestPermissions(result)
            "isBluetoothEnabled" -> result.success(isBluetoothEnabled())
            "isRunning" -> result.success(running)
            "startMesh" -> {
                if (!hasPermissions()) {
                    return result.error(
                        "PERMISSION_DENIED",
                        "Bluetooth permissions are required for mesh mode",
                        null
                    )
                }
                if (!isBluetoothEnabled()) {
                    return result.error(
                        "BLUETOOTH_OFF",
                        "Bluetooth is switched off",
                        null
                    )
                }
                try {
                    if (!running) {
                        nativeStartMesh()
                        running = true
                    }
                    result.success(true)
                } catch (e: Throwable) {
                    // A failure to start must leave `running` false, or the UI
                    // would show mesh as active while nothing is advertising.
                    running = false
                    result.error("MESH_START_FAILED", e.message, e.stackTraceToString())
                }
            }
            "stopMesh" -> {
                try {
                    if (running) {
                        nativeStopMesh()
                    }
                } finally {
                    running = false
                }
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    private fun hasPermissions(): Boolean = requiredPermissions().all {
        ContextCompat.checkSelfPermission(appContext, it) == PackageManager.PERMISSION_GRANTED
    }

    private fun isBluetoothEnabled(): Boolean {
        val manager = appContext.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        return manager?.adapter?.isEnabled == true
    }

    private fun requestPermissions(result: Result) {
        if (hasPermissions()) {
            return result.success(true)
        }
        val currentActivity = activity
            ?: return result.error("NO_ACTIVITY", "Cannot request permissions without an activity", null)

        // Only one request may be outstanding: Android delivers a single
        // callback per request code, so a second concurrent request would
        // leave the first Dart future hanging forever.
        pendingPermissionResult?.let {
            return result.error("REQUEST_IN_FLIGHT", "A permission request is already in progress", null)
        }
        pendingPermissionResult = result
        ActivityCompat.requestPermissions(currentActivity, requiredPermissions(), PERMISSION_REQUEST_CODE)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ): Boolean {
        if (requestCode != PERMISSION_REQUEST_CODE) return false
        val result = pendingPermissionResult ?: return false
        pendingPermissionResult = null
        val granted = grantResults.isNotEmpty() &&
            grantResults.all { it == PackageManager.PERMISSION_GRANTED }
        result.success(granted)
        return true
    }
}
