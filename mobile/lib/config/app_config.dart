import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Application configuration.
///
/// The relay URL was previously a compile-time `String.fromEnvironment`
/// constant defaulting to `http://127.0.0.1:8080`. That made the app
/// unusable on a real device without rebuilding it — the single most
/// direct blocker to anyone actually running this. It is now runtime
/// settable and persisted; the compile-time value survives only as the
/// initial default, so existing `--dart-define` build commands keep
/// working.
class AppConfig {
  AppConfig._();

  static const _storage = FlutterSecureStorage();
  static const _relayUrlKey = 'parda_relay_url';
  static const _meshEnabledKey = 'parda_mesh_enabled';

  /// Compile-time default, overridable at build time:
  ///   flutter run --dart-define=PARDA_RELAY_URL=https://relay.example.com
  ///
  /// `127.0.0.1` is the right default for a *physical device* bridged
  /// with `adb reverse tcp:8080 tcp:8080`, and for desktop. On an
  /// Android emulator the host is `10.0.2.2` instead — the Settings
  /// screen offers both as one-tap presets rather than making the user
  /// know that.
  static const String defaultRelayUrl = String.fromEnvironment(
    'PARDA_RELAY_URL',
    defaultValue: 'http://127.0.0.1:8080',
  );

  /// Loopback host as seen from inside an Android emulator.
  static const String emulatorRelayUrl = 'http://10.0.2.2:8080';

  static String _relayBaseUrl = defaultRelayUrl;

  /// Current relay base URL. Synchronous so call sites (which are on hot
  /// paths like polling) do not each have to await storage; [load] must
  /// run once at startup to populate it.
  static String get relayBaseUrl => _relayBaseUrl;

  static bool _meshEnabled = false;
  static bool get meshEnabled => _meshEnabled;

  /// Read persisted settings. Call once, before the first frame.
  static Future<void> load() async {
    try {
      _relayBaseUrl = await _storage.read(key: _relayUrlKey) ?? defaultRelayUrl;
      _meshEnabled = (await _storage.read(key: _meshEnabledKey)) == 'true';
    } catch (_) {
      // Secure storage can fail on a device whose keystore is in a bad
      // state. Falling back to defaults keeps the app usable rather than
      // failing to start over a settings read.
      _relayBaseUrl = defaultRelayUrl;
      _meshEnabled = false;
    }
  }

  static Future<void> setRelayBaseUrl(String url) async {
    _relayBaseUrl = _normalise(url);
    await _storage.write(key: _relayUrlKey, value: _relayBaseUrl);
  }

  static Future<void> setMeshEnabled(bool enabled) async {
    _meshEnabled = enabled;
    await _storage.write(key: _meshEnabledKey, value: enabled.toString());
  }

  /// Trim and drop a trailing slash, so `http://host:8080/` and
  /// `http://host:8080` do not produce double-slashed request paths.
  static String _normalise(String url) {
    var u = url.trim();
    while (u.endsWith('/')) {
      u = u.substring(0, u.length - 1);
    }
    return u;
  }

  /// Device ID — always 1 (single-device per identity).
  static const int deviceId = 1;

  /// Size of the one-time prekey pool generated at enrollment.
  static const int preKeyPoolSize = 100;

  /// Relay polling interval. A real deployment would use push or a
  /// WebSocket; polling is what the relay's REST surface supports today.
  static const Duration pollInterval = Duration(seconds: 3);
}
