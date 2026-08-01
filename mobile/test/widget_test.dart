// Minimal smoke test, replacing `flutter create`'s counter-app
// boilerplate (which referenced `MyApp`, a class that doesn't exist in
// this project — found while scaffolding the Android platform files in
// Sub-Phase 4.5B). This only confirms `PardaApp` builds without
// throwing; it does not exercise `SessionService`/`SignalBridge` (those
// need a running platform-channel handler, which a plain widget test
// doesn't provide) — that's what the Sub-Phase 4.5B/4.5C instrumented
// tests are for.

import 'package:flutter_test/flutter_test.dart';

import 'package:parda_mobile/main.dart';

void main() {
  testWidgets('PardaApp builds and shows onboarding when not yet enrolled', (WidgetTester tester) async {
    await tester.pumpWidget(const PardaApp());
    await tester.pump();

    expect(find.text('PARDA'), findsOneWidget);
  });
}
