import 'package:flutter/services.dart';

/// Bridge to native libsignal-android via MethodChannel.
///
/// All cryptographic operations run in native platform code
/// (`SignalPlugin.kt` → `org.signal.libsignal.protocol.*`). Identity and
/// session state lives in `PersistentSignalStore`, encrypted at rest
/// under an Android Keystore master key — see that class's docs for what
/// that does and does not mean.
///
/// The Dart layer never handles raw private key bytes, and since
/// Sub-Phase 4.5C it never handles decrypted message bytes either:
/// [decryptMessage] returns an opaque native handle.
class SignalBridge {
  static const MethodChannel _channel = MethodChannel('com.parda.app/signal');

  /// `true` if this device already holds a generated identity.
  ///
  /// The authoritative enrollment check. Previously the app inferred
  /// enrollment from a user ID stored on the Dart side, which could be
  /// present while the native key store was empty — leaving the app
  /// permanently stuck in a state where every send failed.
  Future<bool> isEnrolled() async =>
      await _channel.invokeMethod<bool>('isEnrolled') ?? false;

  /// The enrolled user ID, or `null` if this device has not enrolled.
  Future<String?> localUserId() async =>
      await _channel.invokeMethod<String>('localUserId');

  /// Generate a new identity, persist it, and return the prekey bundle
  /// to publish to the relay. Replaces any existing identity.
  Future<Map<String, dynamic>> generateIdentity(
    String userId,
    int registrationId,
  ) async {
    final result = await _channel.invokeMethod<Map>('generateIdentity', {
      'userId': userId,
      'registrationId': registrationId,
    });
    return Map<String, dynamic>.from(result!);
  }

  /// The current prekey bundle, rebuilt from live key material — used to
  /// re-publish after a relay reset.
  Future<Map<String, dynamic>> getLocalPreKeyBundle() async {
    final result = await _channel.invokeMethod<Map>('getPreKeyBundle');
    return Map<String, dynamic>.from(result!);
  }

  /// Perform X3DH against [bundle], establishing a session with
  /// [remoteUserId].
  Future<void> processPreKeyBundle(
    String remoteUserId,
    Map<String, dynamic> bundle,
  ) async {
    await _channel.invokeMethod<void>('processPreKeyBundle', {
      'remoteUserId': remoteUserId,
      'bundle': bundle,
    });
  }

  /// Encrypt [plaintext] for [remoteUserId], returning a `MessageEnvelope`
  /// JSON map ready to POST to the relay.
  Future<Map<String, dynamic>> encryptMessage(
    String remoteUserId,
    Uint8List plaintext,
  ) async {
    final result = await _channel.invokeMethod<Map>('encryptMessage', {
      'remoteUserId': remoteUserId,
      'plaintext': plaintext,
    });
    return Map<String, dynamic>.from(result!);
  }

  /// Decrypt an incoming envelope.
  ///
  /// Returns a native `PlaintextHandle` ID, **not** the decrypted bytes —
  /// Sub-Phase 4.5C's fix for the Dart plaintext problem. See
  /// `plaintext_handle.dart` and
  /// `docs/phase4.5c-dart-plaintext-design.md`.
  Future<int> decryptMessage(Map<String, dynamic> envelopeJson) async {
    final result = await _channel.invokeMethod<int>('decryptMessage', {
      'envelope': envelopeJson,
    });
    return result!;
  }

  Future<bool> hasSession(String remoteUserId) async =>
      await _channel.invokeMethod<bool>('hasSession', {
        'remoteUserId': remoteUserId,
      }) ??
      false;

  /// Every peer this device holds a session with — survives restart, so
  /// the conversation list can be rebuilt after the app is killed.
  Future<List<String>> knownPeers() async {
    final result = await _channel.invokeMethod<List>('knownPeers');
    return (result ?? const []).cast<String>();
  }

  /// The 60-digit safety number for a conversation (Sub-Phase 4.5D).
  ///
  /// Byte-compatible with `protocol/src/trust.rs`'s `Fingerprint` —
  /// inspired by Signal's safety-number concept, explicitly not
  /// bit-compatible with Signal's own algorithm.
  Future<String> safetyNumber(String remoteUserId) async {
    final result = await _channel.invokeMethod<Map>('safetyNumber', {
      'remoteUserId': remoteUserId,
    });
    return Map<String, dynamic>.from(result!)['digits'] as String;
  }

  /// Remove all session and trust state for one conversation.
  ///
  /// Carries the same documented limit as the Rust `burn_conversation`:
  /// the conversation becomes unusable (real and observable), but
  /// libsignal's own non-zeroizing internals may retain copies no code
  /// here can reach. See `docs/phase3-3a-self-destruct-design.md` §12.
  Future<void> burnConversation(String remoteUserId) async {
    await _channel.invokeMethod<void>('burnConversation', {
      'remoteUserId': remoteUserId,
    });
  }

  /// Erase this device's identity entirely.
  Future<void> wipeIdentity() async {
    await _channel.invokeMethod<void>('wipeIdentity');
  }

  // ── Physical (QR) key exchange ──────────────────────────────────────

  /// This device's contact card, for display as a QR code.
  Future<Map<String, dynamic>> contactCard() async {
    final result = await _channel.invokeMethod<Map>('contactCard');
    return Map<String, dynamic>.from(result!);
  }

  /// Establish a session from a scanned card and mark the peer verified.
  ///
  /// Throws [PlatformException] with code `IDENTITY_CHANGED` when the
  /// card contradicts a key already verified for that user ID, and
  /// `SELF_CARD` when scanning one's own card.
  Future<String> importContact(Map<String, dynamic> card) async {
    final result = await _channel.invokeMethod<Map>('importContact', {'card': card});
    return Map<String, dynamic>.from(result!)['user_id'] as String;
  }

  /// `true` if this peer's key was confirmed out-of-band.
  Future<bool> isVerified(String remoteUserId) async =>
      await _channel.invokeMethod<bool>('isVerified', {
        'remoteUserId': remoteUserId,
      }) ??
      false;

  /// Record the peer's current identity key as verified — the manual
  /// counterpart to importing a scanned contact card.
  Future<void> markVerified(String remoteUserId) async {
    await _channel.invokeMethod<void>('markVerified', {
      'remoteUserId': remoteUserId,
    });
  }

  /// Drop a verification, returning the peer to trust-on-first-use — the
  /// escape hatch for a peer who genuinely reinstalled.
  Future<void> forgetVerification(String remoteUserId) async {
    await _channel.invokeMethod<void>('forgetVerification', {
      'remoteUserId': remoteUserId,
    });
  }

  // ── Encrypted local history ─────────────────────────────────────────

  Future<bool> historyEnabled() async =>
      await _channel.invokeMethod<bool>('historyEnabled') ?? false;

  Future<void> setHistoryEnabled(bool enabled) async {
    await _channel.invokeMethod<void>('setHistoryEnabled', {'enabled': enabled});
  }

  Future<List<Map<String, dynamic>>> loadHistory(String peer) async {
    final result = await _channel.invokeMethod<List>('loadHistory', {'peer': peer});
    return (result ?? const [])
        .map((e) => Map<String, dynamic>.from(e as Map))
        .toList();
  }

  Future<void> appendHistory({
    required String id,
    required String peer,
    required String senderId,
    required String body,
    required int timestampMs,
    required bool outgoing,
  }) async {
    await _channel.invokeMethod<void>('appendHistory', {
      'id': id,
      'peer': peer,
      'senderId': senderId,
      'body': body,
      'ts': timestampMs,
      'outgoing': outgoing,
    });
  }
}
