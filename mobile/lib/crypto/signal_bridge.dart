import 'dart:typed_data';
import 'package:flutter/services.dart';

/// Bridge to native libsignal-android / libsignal-swift via MethodChannel.
///
/// All cryptographic operations are performed in native platform code, where:
/// - Android: uses libsignal-android + Android Keystore (StrongBox if available)
/// - iOS:     uses libsignal-swift + iOS Secure Enclave
///
/// The Dart layer never handles raw private key bytes. All key material
/// stays inside the platform's hardware security module.
///
/// ## Method channel contract
///
/// The native plugin (`SignalPlugin.kt` / `SignalPlugin.swift`) exposes
/// the following method channel calls:
///
/// | Method | Arguments | Returns |
/// |--------|-----------|---------|
/// | `generateIdentity` | `{ registrationId: int }` | `PreKeyBundleJson` |
/// | `getPreKeyBundle` | — | `PreKeyBundleJson` |
/// | `processPreKeyBundle` | `{ remoteUserId: String, bundle: Map }` | `void` |
/// | `encryptMessage` | `{ remoteUserId: String, plaintext: Uint8List }` | `EnvelopeJson` |
/// | `decryptMessage` | `{ envelope: Map }` | `Uint8List` |
/// | `hasSession` | `{ remoteUserId: String }` | `bool` |
class SignalBridge {
  static const MethodChannel _channel = MethodChannel('com.parda.app/signal');

  /// Generate a new identity and upload a prekey bundle.
  ///
  /// Must be called once on first launch. Returns the serialised prekey
  /// bundle that should be uploaded to the relay server.
  Future<Map<String, dynamic>> generateIdentity(int registrationId) async {
    final result = await _channel.invokeMethod<Map>('generateIdentity', {
      'registrationId': registrationId,
    });
    return Map<String, dynamic>.from(result!);
  }

  /// Retrieve the locally-stored prekey bundle (for re-upload after server reset).
  Future<Map<String, dynamic>> getLocalPreKeyBundle() async {
    final result = await _channel.invokeMethod<Map>('getPreKeyBundle');
    return Map<String, dynamic>.from(result!);
  }

  /// Initiate a session with a remote peer using their prekey bundle.
  ///
  /// Must be called before [encryptMessage] for a new contact.
  /// Internally performs X3DH key agreement on the native side.
  Future<void> processPreKeyBundle(
    String remoteUserId,
    Map<String, dynamic> bundle,
  ) async {
    await _channel.invokeMethod<void>('processPreKeyBundle', {
      'remoteUserId': remoteUserId,
      'bundle': bundle,
    });
  }

  /// Encrypt [plaintext] for [remoteUserId].
  ///
  /// Returns a map matching the `MessageEnvelope` JSON shape expected
  /// by the relay server. The `ciphertext` field is base64-encoded.
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

  /// Decrypt an incoming envelope map fetched from the relay server.
  ///
  /// Returns the plaintext bytes. If the envelope is a PreKey message,
  /// the native side establishes a new session automatically.
  Future<Uint8List> decryptMessage(Map<String, dynamic> envelopeJson) async {
    final result = await _channel.invokeMethod<Uint8List>('decryptMessage', {
      'envelope': envelopeJson,
    });
    return result!;
  }

  /// Returns `true` if an active session exists for [remoteUserId].
  Future<bool> hasSession(String remoteUserId) async {
    return await _channel.invokeMethod<bool>('hasSession', {
      'remoteUserId': remoteUserId,
    }) ??
        false;
  }
}
