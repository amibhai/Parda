/// Application-wide configuration constants.
///
/// In production these would be loaded from environment-specific config files
/// or a secure configuration service. For Phase 1, the relay URL is
/// hard-coded to localhost for local development.
class AppConfig {
  AppConfig._();

  /// Base URL of the PARDA relay server.
  ///
  /// Override with environment variable PARDA_RELAY_URL at build time:
  ///   flutter run --dart-define=PARDA_RELAY_URL=https://relay.example.com
  static const String relayBaseUrl = String.fromEnvironment(
    'PARDA_RELAY_URL',
    defaultValue: 'http://127.0.0.1:8080',
  );

  /// Device ID — always 1 in Phase 1 (single-device per identity).
  static const int deviceId = 1;

  /// Maximum number of one-time prekeys to maintain in the pool.
  static const int preKeyPoolSize = 100;

  /// Minimum pool size before triggering a prekey replenishment upload.
  static const int preKeyReplenishThreshold = 10;

  /// Message polling interval in Phase 1 (replace with push/WebSocket in Phase 2).
  static const Duration pollInterval = Duration(seconds: 5);

  /// Phase 1 feature flags — none of these are active yet.
  static const bool sealedSenderEnabled = false;   // Phase 2
  static const bool mixNetworkEnabled   = false;   // Phase 2
  static const bool selfDestructEnabled = false;   // Phase 3
  static const bool offlineMeshEnabled  = false;   // Phase 4
}
