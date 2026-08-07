import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'config/app_config.dart';
import 'screens/home_screen.dart';
import 'screens/onboarding_screen.dart';
import 'services/session_service.dart';
import 'theme/app_theme.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // Settings must be read before the first frame — the relay URL is
  // consulted synchronously by every network call.
  await AppConfig.load();
  runApp(const PardaApp());
}

class PardaApp extends StatelessWidget {
  const PardaApp({super.key});

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider(
      create: (_) => SessionService()..restore(),
      child: MaterialApp(
        title: 'PARDA',
        debugShowCheckedModeBanner: false,
        theme: AppTheme.dark(),
        home: const _AppRoot(),
      ),
    );
  }
}

/// Decides between the splash, onboarding, and the home screen.
class _AppRoot extends StatelessWidget {
  const _AppRoot();

  @override
  Widget build(BuildContext context) {
    final session = context.watch<SessionService>();

    // Enrollment state is resolved asynchronously from the native key
    // store. Showing onboarding before that resolves would flash the
    // enrollment screen at an already-enrolled user on every launch.
    if (!session.isInitialised) {
      return const _SplashScreen();
    }
    return session.isEnrolled ? const HomeScreen() : const OnboardingScreen();
  }
}

class _SplashScreen extends StatelessWidget {
  const _SplashScreen();

  @override
  Widget build(BuildContext context) {
    return const Scaffold(
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            BrandMark(size: 72, glow: true),
            SizedBox(height: 28),
            SizedBox(
              width: 20,
              height: 20,
              child: CircularProgressIndicator(strokeWidth: 2),
            ),
          ],
        ),
      ),
    );
  }
}
