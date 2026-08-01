import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/widgets.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:uuid/uuid.dart';

import '../config/app_config.dart';
import '../crypto/plaintext_handle.dart';
import '../crypto/signal_bridge.dart';
import '../models/message.dart';
import 'api_service.dart';

/// Manages the full session lifecycle for PARDA messaging.
///
/// Responsibilities:
/// - First-run identity generation and relay registration
/// - Initiating sessions with new contacts (X3DH via [SignalBridge])
/// - Encrypting outbound messages and submitting to relay
/// - Polling relay for inbound envelopes and decrypting them
/// - Persisting decrypted messages to the local SQLite store
///
/// All crypto operations delegate to [SignalBridge] (native platform code).
/// This service never holds plaintext private key material.
///
/// ## Sub-Phase 4.5C: native plaintext handle lifecycle
///
/// A received message's decrypted content lives behind a native
/// [PlaintextHandle], not a cached Dart `String` (see
/// `models/message.dart`, `docs/phase4.5c-dart-plaintext-design.md`).
/// Releasing (zeroizing) a handle the moment its chat bubble scrolls
/// off-screen was considered and rejected: this app keeps no persistent
/// message history (`Message.toJson`/`fromJson` don't exist — nothing
/// backs a re-fetch), and the relay's `GET` is fetch-and-clear, so a
/// released handle could never be repopulated — scrolling away and back
/// within the same session would permanently lose that message, a real
/// usability regression, not just a theoretical one. Instead,
/// [SessionService] mixes in [WidgetsBindingObserver] and releases every
/// outstanding handle when the app is backgrounded or terminated
/// ([AppLifecycleState.paused]/[AppLifecycleState.detached]) — this
/// still narrows the exposure window materially (from "as long as the
/// process happens to stay alive, possibly hours" to "until the app
/// leaves the foreground") without breaking in-session scroll-back.
class SessionService extends ChangeNotifier with WidgetsBindingObserver {
  final SignalBridge _signal;
  final ApiService _api;
  final FlutterSecureStorage _secureStorage;
  final _uuid = const Uuid();

  /// Local user identifier (set during enrollment).
  String? _localUserId;
  String? get localUserId => _localUserId;

  /// Locally-cached messages by conversation ID.
  final Map<String, List<Message>> _messages = {};
  Map<String, List<Message>> get messages => Map.unmodifiable(_messages);

  /// Every [PlaintextHandle] currently backing a received message's
  /// content, released in bulk on backgrounding — see class docs.
  final List<PlaintextHandle> _livePlaintextHandles = [];

  /// Active polling timer.
  Timer? _pollTimer;

  SessionService({
    SignalBridge? signal,
    ApiService? api,
    FlutterSecureStorage? secureStorage,
  })  : _signal = signal ?? SignalBridge(),
        _api = api ?? ApiService(),
        _secureStorage = secureStorage ?? const FlutterSecureStorage() {
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused || state == AppLifecycleState.detached) {
      _releaseAllPlaintextHandles();
    }
  }

  void _releaseAllPlaintextHandles() {
    for (final handle in _livePlaintextHandles) {
      handle.release();
    }
    _livePlaintextHandles.clear();
  }

  // ── Enrollment ───────────────────────────────────────────────────────────

  /// Check if this device already has a registered identity.
  Future<bool> get isEnrolled async =>
      await _secureStorage.read(key: 'parda_user_id') != null;

  /// Generate a new identity and register with the relay server.
  ///
  /// Should only be called once (first launch). Persists the user ID
  /// in [FlutterSecureStorage].
  Future<void> enroll({String? userId}) async {
    _localUserId = userId ?? _uuid.v4();
    final registrationId = _localUserId.hashCode.abs() % 0x7FFFFFFF;

    // Native: generate identity keys, store in Android Keystore / Secure Enclave
    final bundle = await _signal.generateIdentity(registrationId);

    // Upload prekey bundle to relay
    await _api.uploadPreKeyBundle(_localUserId!, bundle);

    // Persist user ID
    await _secureStorage.write(key: 'parda_user_id', value: _localUserId);

    debugPrint('[SessionService] Enrolled as $_localUserId');
    notifyListeners();
  }

  /// Restore identity from persistent storage (call at app startup).
  Future<void> restore() async {
    _localUserId = await _secureStorage.read(key: 'parda_user_id');
    if (_localUserId != null) {
      _startPolling();
    }
  }

  // ── Session establishment ────────────────────────────────────────────────

  /// Ensure an active Signal session exists for [remoteUserId].
  ///
  /// If no session exists, fetches Bob's prekey bundle from the relay and
  /// performs X3DH key agreement via [SignalBridge].
  Future<void> ensureSession(String remoteUserId) async {
    final hasSession = await _signal.hasSession(remoteUserId);
    if (!hasSession) {
      final bundle = await _api.fetchPreKeyBundle(remoteUserId);
      await _signal.processPreKeyBundle(remoteUserId, bundle);
      debugPrint('[SessionService] Session established with $remoteUserId');
    }
  }

  // ── Sending ──────────────────────────────────────────────────────────────

  /// Encrypt and send a text message to [remoteUserId].
  ///
  /// Returns the locally-created [Message] in [MessageStatus.sending] state.
  Future<Message> sendMessage(String remoteUserId, String body) async {
    assert(_localUserId != null, 'Must call restore() or enroll() first');

    await ensureSession(remoteUserId);

    final localMsg = Message(
      id: _uuid.v4(),
      conversationId: remoteUserId,
      senderId: _localUserId!,
      body: body,
      timestamp: DateTime.now(),
      status: MessageStatus.sending,
    );

    // Optimistically add to local state
    _addMessage(localMsg);

    try {
      // Encrypt via native Signal bridge
      final envelopeJson = await _signal.encryptMessage(
        remoteUserId,
        Uint8List.fromList(utf8.encode(body)),
      );

      // Submit to relay
      await _api.submitMessage(remoteUserId, envelopeJson);

      // Update status to sent
      _updateMessageStatus(localMsg.id, remoteUserId, MessageStatus.sent);
    } catch (e) {
      _updateMessageStatus(localMsg.id, remoteUserId, MessageStatus.failed);
      debugPrint('[SessionService] Send failed: $e');
      rethrow;
    }

    return localMsg;
  }

  // ── Receiving (polling) ──────────────────────────────────────────────────

  /// Start periodic polling for incoming messages.
  void _startPolling() {
    _pollTimer?.cancel();
    _pollTimer = Timer.periodic(AppConfig.pollInterval, (_) => _pollMessages());
    // Poll immediately on start
    _pollMessages();
  }

  /// Fetch pending envelopes from the relay and decrypt them.
  Future<void> _pollMessages() async {
    if (_localUserId == null) return;
    try {
      final envelopes = await _api.fetchMessages(_localUserId!);
      for (final envelopeJson in envelopes) {
        await _processIncomingEnvelope(envelopeJson);
      }
    } catch (e) {
      debugPrint('[SessionService] Poll error: $e');
    }
  }

  Future<void> _processIncomingEnvelope(Map<String, dynamic> envelopeJson) async {
    try {
      final senderId = envelopeJson['envelope']['sender_id'] as String? ??
          envelopeJson['sender_id'] as String;

      // Decrypt via native Signal bridge (establishes session if PreKey
      // message). Sub-Phase 4.5C: this returns a native handle, not the
      // decrypted bytes — see SignalBridge.decryptMessage's docs.
      final handleId = await _signal.decryptMessage(
        envelopeJson['envelope'] as Map<String, dynamic>? ?? envelopeJson,
      );
      final handle = PlaintextHandle(handleId);
      _livePlaintextHandles.add(handle);

      final msg = Message(
        id: envelopeJson['id'] as String? ?? _uuid.v4(),
        conversationId: senderId,
        senderId: senderId,
        plaintextHandleId: handleId,
        timestamp: DateTime.fromMillisecondsSinceEpoch(
          envelopeJson['envelope']?['timestamp_ms'] as int? ??
              DateTime.now().millisecondsSinceEpoch,
        ),
        status: MessageStatus.received,
      );

      _addMessage(msg);
      debugPrint('[SessionService] Received message from $senderId');
    } catch (e) {
      debugPrint('[SessionService] Decrypt error: $e');
    }
  }

  // ── Local message store ──────────────────────────────────────────────────

  void _addMessage(Message msg) {
    _messages.putIfAbsent(msg.conversationId, () => []).add(msg);
    notifyListeners();
  }

  void _updateMessageStatus(
    String msgId,
    String conversationId,
    MessageStatus status,
  ) {
    final convo = _messages[conversationId];
    if (convo == null) return;
    final idx = convo.indexWhere((m) => m.id == msgId);
    if (idx != -1) {
      convo[idx] = convo[idx].copyWith(status: status);
      notifyListeners();
    }
  }

  List<Message> messagesFor(String conversationId) =>
      _messages[conversationId] ?? [];

  @override
  void dispose() {
    _pollTimer?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    _releaseAllPlaintextHandles();
    super.dispose();
  }
}
