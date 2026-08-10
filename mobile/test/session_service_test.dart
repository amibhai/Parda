// Covers the receive path, and specifically the bug that made received
// messages vanish.
//
// Persisting a received message used to happen when a chat bubble
// rendered it out of its native handle. Handles are released whenever
// the app leaves the foreground, and most messages arrive while the user
// is looking somewhere else — so the handle was routinely gone before
// anything read it and the message was lost permanently despite history
// being switched on. Reading at receipt fixed it; these tests pin that
// behaviour, and the handle-only path that history-off still uses.

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:parda_mobile/services/api_service.dart';
import 'package:parda_mobile/services/session_service.dart';

const _signalChannel = MethodChannel('com.parda.app/signal');
const _plaintextChannel = MethodChannel('com.parda.app/plaintext');
const _meshChannel = MethodChannel('com.parda.app/mesh');

/// Serves one inbound envelope, then nothing — mirroring the relay's
/// fetch-and-clear behaviour, which is exactly why a dropped message
/// cannot be recovered by polling again.
class _OneShotApi extends ApiService {
  bool _served = false;
  @override
  Future<List<Map<String, dynamic>>> fetchMessages(String userId) async {
    if (_served) return [];
    _served = true;
    return [
      {
        'id': 'msg-1',
        'sender_id': 'bob',
        'recipient_id': userId,
        'ciphertext': 'AAAA',
        'envelope_type': 'ratchet',
        'timestamp_ms': 1700000000000,
        'version': 2,
        'sealed_sender': false,
      }
    ];
  }

  @override
  Future<bool> healthCheck() async => true;
}

/// `restore()` kicks off a poll it does not await, so the inbound
/// message lands a few event-loop turns later. Wait for it rather than
/// assuming an ordering the production code never promised.
Future<void> waitFor(bool Function() condition, {String? reason}) async {
  for (var i = 0; i < 100; i++) {
    if (condition()) return;
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
  fail(reason ?? 'condition never became true');
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  late List<MethodCall> signalCalls;
  late bool historyEnabled;
  late bool handleReleased;

  void installMocks({required bool history}) {
    signalCalls = [];
    historyEnabled = history;
    handleReleased = false;

    messenger.setMockMethodCallHandler(_signalChannel, (call) async {
      signalCalls.add(call);
      switch (call.method) {
        case 'isEnrolled':
          return true;
        case 'localUserId':
          return 'me';
        case 'knownPeers':
          return <String>[];
        case 'historyEnabled':
          return historyEnabled;
        case 'loadHistory':
          return <Map<String, dynamic>>[];
        case 'decryptMessage':
          return 42; // a native plaintext handle
        case 'appendHistory':
          return null;
        default:
          return null;
      }
    });

    messenger.setMockMethodCallHandler(_plaintextChannel, (call) async {
      switch (call.method) {
        case 'copyInto':
          // Flutter hands back an unmodifiable view in production; the
          // code must not try to scrub it. Returning a plain list here
          // still exercises the decode path.
          return Uint8List.fromList('hello from bob'.codeUnits);
        case 'release':
          handleReleased = true;
          return null;
        default:
          return null;
      }
    });

    messenger.setMockMethodCallHandler(_meshChannel, (call) async => false);
  }

  tearDown(() {
    messenger.setMockMethodCallHandler(_signalChannel, null);
    messenger.setMockMethodCallHandler(_plaintextChannel, null);
    messenger.setMockMethodCallHandler(_meshChannel, null);
  });

  test('a received message is read and persisted at receipt, not at render',
      () async {
    installMocks(history: true);
    final service = SessionService(api: _OneShotApi());
    await service.restore();
    await waitFor(() => service.messagesFor('bob').isNotEmpty,
        reason: 'the inbound message never arrived');

    final msgs = service.messagesFor('bob');
    expect(msgs, hasLength(1));

    // The text is on the message immediately — no bubble has rendered
    // anything yet. This is the regression: it used to be null here, and
    // the handle was released before anything could read it.
    expect(msgs.single.body, 'hello from bob');

    final appended = signalCalls.where((c) => c.method == 'appendHistory');
    expect(appended, hasLength(1),
        reason: 'the message must reach encrypted history without a render');
    expect(appended.single.arguments['body'], 'hello from bob');
    expect(appended.single.arguments['peer'], 'bob');
    expect(appended.single.arguments['outgoing'], false);

    // Holding the native buffer open past that point buys nothing.
    expect(handleReleased, isTrue);

    service.dispose();
  });

  test('with history off the message keeps a handle and is not written down',
      () async {
    installMocks(history: false);
    final service = SessionService(api: _OneShotApi());
    await service.restore();
    await waitFor(() => service.messagesFor('bob').isNotEmpty,
        reason: 'the inbound message never arrived');

    final msgs = service.messagesFor('bob');
    expect(msgs, hasLength(1));

    // The stricter posture the setting promises: nothing stored, and the
    // text only reachable through the native handle.
    expect(msgs.single.body, isNull);
    expect(msgs.single.plaintextHandleId, 42);
    expect(signalCalls.where((c) => c.method == 'appendHistory'), isEmpty);

    service.dispose();
  });

  test('a conversation appears for the sender of an inbound message', () async {
    installMocks(history: true);
    final service = SessionService(api: _OneShotApi());
    await service.restore();
    await waitFor(() => service.conversations.contains('bob'));

    expect(service.conversations, contains('bob'));
    service.dispose();
  });

  test('polling twice does not duplicate a message', () async {
    installMocks(history: true);
    final service = SessionService(api: _OneShotApi());
    await service.restore();
    await waitFor(() => service.messagesFor('bob').isNotEmpty);
    await service.pollNow();
    await service.pollNow();

    expect(service.messagesFor('bob'), hasLength(1));
    service.dispose();
  });
}
