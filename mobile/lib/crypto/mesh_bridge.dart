import 'package:flutter/services.dart';

/// Dart-facing control surface for offline mesh mode (Sub-Phase 4.5B).
///
/// Wraps `MeshPlugin.kt`, which owns the Android runtime-permission flow
/// and starts/stops the Rust `MeshNode` sync and accept loops via JNI.
///
/// ## What running mesh mode actually does, and what is unverified
///
/// Starting mesh mode makes this device advertise a rotating opaque
/// `AdvertToken` over BLE, scan for peers doing the same, and
/// store-and-forward bundles it is handed. **Whether that exchange
/// completes against another real device has not been verified** — this
/// project has never had two devices running it simultaneously. See the
/// README's Status & Limitations. Turning it on is safe to try; it may
/// simply find nothing.
class MeshBridge {
  static const MethodChannel _channel = MethodChannel('com.parda.app/mesh');

  /// `true` if the BLE runtime permissions are already granted.
  Future<bool> hasPermissions() async =>
      await _channel.invokeMethod<bool>('hasPermissions') ?? false;

  /// Show the system permission prompt. Resolves to the user's decision.
  Future<bool> requestPermissions() async =>
      await _channel.invokeMethod<bool>('requestPermissions') ?? false;

  /// `true` if the Bluetooth adapter is switched on. Mesh mode cannot
  /// start without it, and this is a user action the app cannot perform
  /// on their behalf on modern Android.
  Future<bool> isBluetoothEnabled() async =>
      await _channel.invokeMethod<bool>('isBluetoothEnabled') ?? false;

  Future<bool> isRunning() async =>
      await _channel.invokeMethod<bool>('isRunning') ?? false;

  /// Start advertising, scanning, and relaying.
  ///
  /// Throws [PlatformException] with code `PERMISSION_DENIED` or
  /// `BLUETOOTH_OFF` when the precondition is not met — deliberately an
  /// error rather than a silent no-op, so the UI can tell the user
  /// exactly which thing to fix.
  Future<void> start() async {
    await _channel.invokeMethod<bool>('startMesh');
  }

  Future<void> stop() async {
    await _channel.invokeMethod<void>('stopMesh');
  }
}
