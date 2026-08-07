// Smoke test for the app's startup routing.
//
// `PardaApp` now resolves enrollment asynchronously from the *native*
// key store rather than from a Dart-side flag, so the first frame is a
// splash and the onboarding/home decision comes a frame later. That is
// deliberate — the previous behaviour flashed the enrollment screen at
// an already-enrolled user on every launch — and it means this test has
// to mock the platform channel and settle, rather than asserting on the
// first pump.

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:parda_mobile/main.dart';

const _signalChannel = MethodChannel('com.parda.app/signal');
const _meshChannel = MethodChannel('com.parda.app/mesh');

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  setUp(() {
    // Stand in for `SignalPlugin`/`MeshPlugin`. Without this the calls
    // raise MissingPluginException, which the service catches — the app
    // would still reach onboarding, but for the wrong reason, so the
    // test would pass without proving the not-enrolled path works.
    messenger.setMockMethodCallHandler(_signalChannel, (call) async {
      switch (call.method) {
        case 'isEnrolled':
          return false;
        case 'localUserId':
          return null;
        case 'knownPeers':
          return <String>[];
        default:
          return null;
      }
    });
    messenger.setMockMethodCallHandler(_meshChannel, (call) async => false);
  });

  tearDown(() {
    messenger.setMockMethodCallHandler(_signalChannel, null);
    messenger.setMockMethodCallHandler(_meshChannel, null);
  });

  testWidgets('shows onboarding when the native store holds no identity',
      (WidgetTester tester) async {
    await tester.pumpWidget(const PardaApp());
    await tester.pumpAndSettle();

    expect(find.text('PARDA'), findsOneWidget);
    expect(find.text('Generate keys & enroll'), findsOneWidget);
  });

  testWidgets('goes straight to the conversation list when already enrolled',
      (WidgetTester tester) async {
    messenger.setMockMethodCallHandler(_signalChannel, (call) async {
      switch (call.method) {
        case 'isEnrolled':
          return true;
        case 'localUserId':
          return 'alpha-1';
        case 'knownPeers':
          return <String>[];
        default:
          return null;
      }
    });

    await tester.pumpWidget(const PardaApp());
    await tester.pumpAndSettle();

    // The enrolled user's ID is shown in the app bar, and onboarding is
    // not — the regression this guards against is re-prompting someone
    // who already has keys, which would overwrite a working identity.
    expect(find.text('alpha-1'), findsOneWidget);
    expect(find.text('Generate keys & enroll'), findsNothing);
  });
}
