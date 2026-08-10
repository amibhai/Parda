import 'dart:async';
import 'dart:convert';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

import '../config/app_config.dart';
import '../crypto/mesh_bridge.dart';
import '../crypto/plaintext_handle.dart';
import '../crypto/signal_bridge.dart';
import '../models/contact_card.dart';
import '../models/message.dart';
import 'api_service.dart';

/// Whether the relay is currently reachable.
enum RelayStatus { unknown, checking, online, offline }

/// Manages the full session lifecycle for PARDA messaging.
///
/// ## Plaintext handling, and the durability trade it now makes
///
/// A freshly-decrypted message arrives as a native [PlaintextHandle]
/// rather than raw bytes (`docs/phase4.5c-dart-plaintext-design.md`),
/// and every outstanding handle is released when the app leaves the
/// foreground.
///
/// That alone did not survive contact with real use. Handles are gone
/// after backgrounding and the relay's fetch is destructive, so a
/// received message read as permanently unavailable and nothing
/// survived a restart.
///
/// So the behaviour now forks on one setting:
///
/// - **History on** (the default): the plaintext is read out of the
///   handle immediately on receipt, kept on the [Message], written to
///   encrypted history (`MessageStore.kt`), and the handle released.
///   Decrypted content is therefore stored at rest under an Android
///   Keystore key, where it used to be memory-only — a real cost,
///   documented on `MessageStore` and in the README.
/// - **History off**: the handle-only path, unchanged. Nothing is
///   written down, and a message not read before the app is
///   backgrounded is genuinely gone.
///
/// Reading at receipt rather than at render is deliberate and was
/// learned the hard way: most messages arrive while the user is looking
/// elsewhere, so a render-time read found the handle already released
/// and lost the message despite history being on.
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

  bool _historyEnabled = true;
  bool get historyEnabled => _historyEnabled;

  /// Rehydrate every stored conversation.
  ///
  /// Without this the app forgot everything on restart, which is the
  /// difference between a demo and a messenger. Stored messages carry
  /// their text directly — they have no live native handle, and are not
  /// re-decrypted (the ratchet step that produced them is long gone).
  Future<void> _loadHistory() async {
    if (!_historyEnabled) return;
    final localUserId = _localUserId ?? '';
    for (final peer in _peers.toList()) {
      try {
        final rows = await _signal.loadHistory(peer);
        if (rows.isEmpty) continue;
        _messages[peer] = rows
            .map((row) => Message.fromHistory(row, localUserId))
            .toList();
      } catch (e) {
        debugPrint('[SessionService] could not load history for $peer: $e');
      }
    }
  }

  Future<void> setHistoryEnabled(bool enabled) async {
    await _signal.setHistoryEnabled(enabled);
    _historyEnabled = enabled;
    if (!enabled) {
      // The native side has already deleted the stored copies; drop the
      // in-memory mirror too so the UI matches what is actually retained.
      _messages.clear();
    }
    notifyListeners();
  }

  /// Persist a message, best-effort.
  ///
  /// A failure here costs durability, never delivery — the message has
  /// already been sent or received by the time this runs, so it must not
  /// propagate.
  Future<void> _persist(Message msg, String body) async {
    if (!_historyEnabled) return;
    try {
      await _signal.appendHistory(
        id: msg.id,
        peer: msg.conversationId,
        senderId: msg.senderId,
        body: body,
        timestampMs: msg.timestamp.millisecondsSinceEpoch,
        outgoing: msg.isOutgoing,
      );
    } catch (e) {
      debugPrint('[SessionService] could not persist message: $e');
    }
  }

  /// Cache the text a bubble just read out of a native handle, so the
  /// same message renders from memory next time instead of depending on
  /// a handle that may since have been released.
  void cacheRenderedBody(String conversationId, String messageId, String body) {
    final convo = _messages[conversationId];
    if (convo == null) return;
    final idx = convo.indexWhere((m) => m.id == messageId);
    if (idx == -1 || convo[idx].body != null) return;
    convo[idx] = convo[idx].copyWith(body: body);
    unawaited(_persist(convo[idx], body));
  }

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
        _historyEnabled = await _signal.historyEnabled();
        await _loadHistory();
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

  /// The relay this device is currently configured to use. Exposed so
  /// UI can compare it against a scanned card's relay hint.
  String get relayBaseUrl => AppConfig.relayBaseUrl;

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

  /// This device's contact card, tagged with the relay it is using so a
  /// scanner can adopt the same one.
  Future<ContactCard> contactCard() async {
    final raw = await _signal.contactCard();
    return ContactCard(raw).withRelay(AppConfig.relayBaseUrl);
  }

  /// Import a scanned card: opens a session from keys that never touched
  /// the relay, and records the peer as verified.
  ///
  /// Optionally adopts the relay the card advertises — without a shared
  /// relay the two devices can verify each other perfectly and still
  /// have nowhere to exchange messages, which is a confusing way to
  /// fail.
  Future<String> importContact(ContactCard card, {bool adoptRelay = false}) async {
    if (adoptRelay && card.relayUrl != null && card.relayUrl!.isNotEmpty) {
      await setRelayUrl(card.relayUrl!);
    }
    final peer = await _signal.importContact(card.raw);
    _peers.add(peer);
    notifyListeners();
    // Publishing is what lets the *other* side reach this device through
    // the relay. Best-effort: a failure here does not undo a verified
    // session, and Settings offers a manual retry.
    unawaited(_republishQuietly());
    return peer;
  }

  Future<void> _republishQuietly() async {
    try {
      await republishBundle();
    } catch (e) {
      debugPrint('[SessionService] bundle re-publish after import failed: $e');
    }
  }

  Future<bool> isVerified(String remoteUserId) => _signal.isVerified(remoteUserId);

  Future<void> markVerified(String remoteUserId) async {
    await _signal.markVerified(remoteUserId);
    notifyListeners();
  }

  Future<void> forgetVerification(String remoteUserId) async {
    await _signal.forgetVerification(remoteUserId);
    notifyListeners();
  }

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
      unawaited(_persist(localMsg, body));
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
      final id = envelopeJson['id'] as String? ?? _localId();
      final timestamp = DateTime.fromMillisecondsSinceEpoch(
        (envelope['timestamp_ms'] as num?)?.toInt() ??
            DateTime.now().millisecondsSinceEpoch,
      );

      // Read the plaintext *now* when history is on, rather than leaving
      // it for whenever a bubble happens to render.
      //
      // Deferring it looked tidier and was wrong: handles are released
      // when the app leaves the foreground, and most messages arrive
      // while the user is not looking at that conversation. The handle
      // was routinely gone before anything read it, so the message
      // showed "no longer available" and was never written to history —
      // permanently lost despite history being enabled. Observed on a
      // Pixel 8 with a message that arrived two minutes before the chat
      // was opened.
      //
      // With history off the handle-only path is kept: nothing is
      // written down, and a message not read before the app is
      // backgrounded is genuinely gone. That is the stricter posture the
      // setting promises, and it is now the only place it applies.
      String? body;
      if (_historyEnabled) {
        final handle = PlaintextHandle(handleId);
        body = await handle.renderCopy();
        // The text is safely in the Message and on its way to storage;
        // holding the native buffer open past that point buys nothing.
        await handle.release();
      } else {
        _livePlaintextHandles.add(PlaintextHandle(handleId));
      }

      final msg = Message(
        id: id,
        conversationId: senderId,
        senderId: senderId,
        body: body,
        plaintextHandleId: body == null ? handleId : null,
        timestamp: timestamp,
        status: MessageStatus.received,
      );

      _peers.add(senderId);
      _addMessage(msg);
      if (body != null) {
        unawaited(_persist(msg, body));
      }
    } catch (e) {
      // A message that arrives and cannot be decrypted used to vanish
      // without trace: the relay's fetch is destructive, so it was gone
      // from the server too, and nothing surfaced the failure. Silence
      // is the worst possible response — the user is left believing
      // nobody wrote to them.
      //
      // The usual cause is a session mismatch: the sender built their
      // session from a stale copy of this device's keys (a screenshotted
      // QR card whose one-time prekey has since been used, or a peer
      // that re-enrolled). Say that, since it is actionable.
      _lastError = 'A message arrived that could not be decrypted. The sender '
          'may be using an out-of-date copy of your keys — share your code '
          'again to start a fresh session.';
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
