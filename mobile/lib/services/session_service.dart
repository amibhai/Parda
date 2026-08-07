import 'dart:async';
import 'dart:convert';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

import '../config/app_config.dart';
import '../crypto/mesh_bridge.dart';
import '../crypto/plaintext_handle.dart';
import '../crypto/signal_bridge.dart';
import '../models/message.dart';
import 'api_service.dart';

/// Whether the relay is currently reachable.
enum RelayStatus { unknown, checking, online, offline }

/// Manages the full session lifecycle for PARDA messaging.
///
/// ## Sub-Phase 4.5C: native plaintext handle lifecycle
///
/// A received message's decrypted content lives behind a native
/// [PlaintextHandle], not a cached Dart `String` (see
/// `models/message.dart`, `docs/phase4.5c-dart-plaintext-design.md`).
/// Releasing a handle the moment its bubble scrolls off-screen was
/// considered and rejected: this app keeps no persistent message
/// history and the relay's fetch is destructive, so a released handle
/// can never be repopulated — scrolling away and back would lose the
/// message. Instead every outstanding handle is released when the app
/// leaves the foreground, which still narrows the window from "as long
/// as the process happens to live" to "until the app is backgrounded".
class SessionService extends ChangeNotifier with WidgetsBindingObserver {
  final SignalBridge _signal;
  final MeshBridge _mesh;
  ApiService _api;

  String? _localUserId;
  String? get localUserId => _localUserId;

  bool _enrolled = false;
  bool get isEnrolled => _enrolled;

  bool _initialised = false;
  bool get isInitialised => _initialised;

  RelayStatus _relayStatus = RelayStatus.unknown;
  RelayStatus get relayStatus => _relayStatus;

  bool _meshRunning = false;
  bool get meshRunning => _meshRunning;

  String? _lastError;
  String? get lastError => _lastError;

  final Map<String, List<Message>> _messages = {};
  Map<String, List<Message>> get messages => Map.unmodifiable(_messages);

  /// Peers with an established session but no messages yet — otherwise a
  /// freshly-started conversation would vanish from the list until the
  /// first message, which reads as the app having forgotten it.
  final Set<String> _peers = {};
  List<String> get conversations {
    final all = {..._peers, ..._messages.keys}.toList();
    all.sort((a, b) {
      final at = _lastActivity(a);
      final bt = _lastActivity(b);
      return bt.compareTo(at);
    });
    return all;
  }

  DateTime _lastActivity(String peer) {
    final msgs = _messages[peer];
    if (msgs == null || msgs.isEmpty) return DateTime.fromMillisecondsSinceEpoch(0);
    return msgs.last.timestamp;
  }

  final List<PlaintextHandle> _livePlaintextHandles = [];
  Timer? _pollTimer;

  SessionService({SignalBridge? signal, MeshBridge? mesh, ApiService? api})
      : _signal = signal ?? SignalBridge(),
        _mesh = mesh ?? MeshBridge(),
        _api = api ?? ApiService() {
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

  // ── Startup ──────────────────────────────────────────────────────────

  /// Restore state at launch.
  ///
  /// Enrollment is decided by the *native* store, not by a Dart-side
  /// flag: the two could previously disagree, leaving the app convinced
  /// it was enrolled while holding no keys.
  Future<void> restore() async {
    try {
      _enrolled = await _signal.isEnrolled();
      _localUserId = _enrolled ? await _signal.localUserId() : null;
      if (_enrolled) {
        _peers.addAll(await _signal.knownPeers());
        _startPolling();
        unawaited(refreshRelayStatus());
        if (AppConfig.meshEnabled) {
          unawaited(setMeshEnabled(true, requestIfNeeded: false));
        }
      }
    } catch (e) {
      _lastError = 'Startup failed: $e';
    } finally {
      _initialised = true;
      notifyListeners();
    }
  }

  // ── Enrollment ───────────────────────────────────────────────────────

  /// Generate an identity and publish its prekey bundle to the relay.
  ///
  /// The identity is generated *and persisted* before the upload is
  /// attempted, so a relay that is unreachable at this moment does not
  /// leave the device half-enrolled — the user can retry the publish
  /// later from Settings rather than starting over.
  Future<void> enroll(String userId) async {
    final registrationId = userId.hashCode.abs() % 0x3FFF + 1;
    final bundle = await _signal.generateIdentity(userId, registrationId);

    _enrolled = true;
    _localUserId = userId;
    notifyListeners();

    await _api.uploadPreKeyBundle(userId, bundle);

    _startPolling();
    unawaited(refreshRelayStatus());
    notifyListeners();
  }

  /// Re-publish this device's prekey bundle — for use after a relay
  /// reset, where the relay has forgotten a still-valid local identity.
  Future<void> republishBundle() async {
    final userId = _localUserId;
    if (userId == null) throw StateError('Not enrolled');
    final bundle = await _signal.getLocalPreKeyBundle();
    await _api.uploadPreKeyBundle(userId, bundle);
  }

  /// Erase this device's identity and all local state.
  Future<void> wipeIdentity() async {
    _pollTimer?.cancel();
    _releaseAllPlaintextHandles();
    await _signal.wipeIdentity();
    _messages.clear();
    _peers.clear();
    _enrolled = false;
    _localUserId = null;
    _relayStatus = RelayStatus.unknown;
    notifyListeners();
  }

  // ── Relay configuration ──────────────────────────────────────────────

  Future<void> setRelayUrl(String url) async {
    await AppConfig.setRelayBaseUrl(url);
    _api = ApiService();
    await refreshRelayStatus();
  }

  Future<void> refreshRelayStatus() async {
    _relayStatus = RelayStatus.checking;
    notifyListeners();
    final ok = await _api.healthCheck();
    _relayStatus = ok ? RelayStatus.online : RelayStatus.offline;
    notifyListeners();
  }

  // ── Mesh ─────────────────────────────────────────────────────────────

  /// Turn offline mesh mode on or off.
  ///
  /// Returns `null` on success, or a human-readable reason it could not
  /// start. Permission and adapter state are surfaced as distinct
  /// messages because they need different user actions.
  Future<String?> setMeshEnabled(bool enabled, {bool requestIfNeeded = true}) async {
    if (!enabled) {
      await _mesh.stop();
      _meshRunning = false;
      await AppConfig.setMeshEnabled(false);
      notifyListeners();
      return null;
    }

    try {
      if (!await _mesh.hasPermissions()) {
        if (!requestIfNeeded) return 'Bluetooth permission not granted';
        final granted = await _mesh.requestPermissions();
        if (!granted) {
          return 'Bluetooth permission is required for mesh mode';
        }
      }
      if (!await _mesh.isBluetoothEnabled()) {
        return 'Turn Bluetooth on to use mesh mode';
      }
      await _mesh.start();
      _meshRunning = true;
      await AppConfig.setMeshEnabled(true);
      notifyListeners();
      return null;
    } on PlatformException catch (e) {
      _meshRunning = false;
      notifyListeners();
      return e.message ?? 'Mesh mode failed to start';
    } catch (e) {
      _meshRunning = false;
      notifyListeners();
      return 'Mesh mode failed to start: $e';
    }
  }

  // ── Sessions ─────────────────────────────────────────────────────────

  /// Ensure a Signal session exists for [remoteUserId], performing X3DH
  /// against their published bundle if not.
  Future<void> ensureSession(String remoteUserId) async {
    if (await _signal.hasSession(remoteUserId)) return;
    final bundle = await _api.fetchPreKeyBundle(remoteUserId);
    await _signal.processPreKeyBundle(remoteUserId, bundle);
    _peers.add(remoteUserId);
    notifyListeners();
  }

  /// Start a conversation without sending anything yet.
  Future<void> startConversation(String remoteUserId) async {
    await ensureSession(remoteUserId);
    _peers.add(remoteUserId);
    notifyListeners();
  }

  Future<String> safetyNumber(String remoteUserId) =>
      _signal.safetyNumber(remoteUserId);

  Future<void> burnConversation(String remoteUserId) async {
    await _signal.burnConversation(remoteUserId);
    for (final m in _messages[remoteUserId] ?? const <Message>[]) {
      final id = m.plaintextHandleId;
      if (id != null) {
        await PlaintextHandle(id).release();
      }
    }
    _messages.remove(remoteUserId);
    _peers.remove(remoteUserId);
    notifyListeners();
  }

  // ── Sending ──────────────────────────────────────────────────────────

  Future<Message> sendMessage(String remoteUserId, String body) async {
    if (_localUserId == null) {
      throw StateError('Not enrolled');
    }
    await ensureSession(remoteUserId);

    final localMsg = Message(
      id: _localId(),
      conversationId: remoteUserId,
      senderId: _localUserId!,
      body: body,
      timestamp: DateTime.now(),
      status: MessageStatus.sending,
    );
    _addMessage(localMsg);

    try {
      final envelopeJson = await _signal.encryptMessage(
        remoteUserId,
        Uint8List.fromList(utf8.encode(body)),
      );
      await _api.submitMessage(remoteUserId, envelopeJson);
      _updateMessageStatus(localMsg.id, remoteUserId, MessageStatus.sent);
    } catch (e) {
      _updateMessageStatus(localMsg.id, remoteUserId, MessageStatus.failed);
      rethrow;
    }
    return localMsg;
  }

  // ── Receiving ────────────────────────────────────────────────────────

  void _startPolling() {
    _pollTimer?.cancel();
    _pollTimer = Timer.periodic(AppConfig.pollInterval, (_) => _pollMessages());
    unawaited(_pollMessages());
  }

  /// Fetch once on demand — backs pull-to-refresh, so a user who
  /// suspects a stuck poll has something to do about it.
  Future<void> pollNow() => _pollMessages();

  Future<void> _pollMessages() async {
    final userId = _localUserId;
    if (userId == null) return;
    try {
      final envelopes = await _api.fetchMessages(userId);
      if (_relayStatus != RelayStatus.online) {
        _relayStatus = RelayStatus.online;
        notifyListeners();
      }
      for (final envelopeJson in envelopes) {
        await _processIncomingEnvelope(envelopeJson);
      }
    } catch (_) {
      if (_relayStatus == RelayStatus.online) {
        _relayStatus = RelayStatus.offline;
        notifyListeners();
      }
    }
  }

  /// Decrypt one fetched envelope and add it to the conversation.
  ///
  /// The relay serialises `StoredEnvelope` with `#[serde(flatten)]`, so
  /// the fields arrive at the top level alongside `id` — there is no
  /// nested `envelope` object. The previous implementation indexed
  /// `envelopeJson['envelope']['sender_id']`, which threw on every
  /// single message; the throw was swallowed by the surrounding catch,
  /// so inbound messages silently never appeared. Parsed defensively
  /// here so either shape works.
  Future<void> _processIncomingEnvelope(Map<String, dynamic> envelopeJson) async {
    try {
      final nested = envelopeJson['envelope'];
      final envelope = nested is Map
          ? Map<String, dynamic>.from(nested)
          : envelopeJson;

      final senderId = envelope['sender_id'] as String?;
      if (senderId == null || senderId.isEmpty) {
        // A sealed-sender envelope carries no sender on the wire by
        // design; this client does not implement that receive path yet,
        // so skipping is correct rather than guessing an identity.
        return;
      }

      final handleId = await _signal.decryptMessage(envelope);
      final handle = PlaintextHandle(handleId);
      _livePlaintextHandles.add(handle);

      final msg = Message(
        id: envelopeJson['id'] as String? ?? _localId(),
        conversationId: senderId,
        senderId: senderId,
        plaintextHandleId: handleId,
        timestamp: DateTime.fromMillisecondsSinceEpoch(
          (envelope['timestamp_ms'] as num?)?.toInt() ??
              DateTime.now().millisecondsSinceEpoch,
        ),
        status: MessageStatus.received,
      );

      _peers.add(senderId);
      _addMessage(msg);
    } catch (e) {
      _lastError = 'Failed to decrypt an incoming message: $e';
      notifyListeners();
    }
  }

  // ── Local state ──────────────────────────────────────────────────────

  int _idCounter = 0;
  String _localId() =>
      '${DateTime.now().microsecondsSinceEpoch}-${_idCounter++}';

  void _addMessage(Message msg) {
    final list = _messages.putIfAbsent(msg.conversationId, () => []);
    // The relay's fetch is destructive, but a retried poll that partly
    // succeeded could still re-present an id; de-duplicate rather than
    // showing the same message twice.
    if (list.any((m) => m.id == msg.id)) return;
    list.add(msg);
    notifyListeners();
  }

  void _updateMessageStatus(String msgId, String conversationId, MessageStatus status) {
    final convo = _messages[conversationId];
    if (convo == null) return;
    final idx = convo.indexWhere((m) => m.id == msgId);
    if (idx != -1) {
      convo[idx] = convo[idx].copyWith(status: status);
      notifyListeners();
    }
  }

  List<Message> messagesFor(String conversationId) =>
      _messages[conversationId] ?? const [];

  void clearError() {
    _lastError = null;
    notifyListeners();
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    _releaseAllPlaintextHandles();
    super.dispose();
  }
}
