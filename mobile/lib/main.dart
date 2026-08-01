import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'services/session_service.dart';
import 'screens/home_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
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
        theme: _buildTheme(),
        home: const _AppRoot(),
      ),
    );
  }

  ThemeData _buildTheme() {
    return ThemeData(
      colorScheme: const ColorScheme.dark(
        primary: Color(0xFF00D084),
        secondary: Color(0xFF0066FF),
        surface: Color(0xFF161B22),
        error: Color(0xFFDA3633),
      ),
      scaffoldBackgroundColor: const Color(0xFF0D1117),
      useMaterial3: true,
    );
  }
}

/// Root widget: decides whether to show onboarding or the home screen.
class _AppRoot extends StatelessWidget {
  const _AppRoot();

  @override
  Widget build(BuildContext context) {
    final session = context.watch<SessionService>();

    if (session.localUserId == null) {
      return const _OnboardingScreen();
    }
    return const HomeScreen();
  }
}

/// First-run onboarding: enrolls the device and uploads a prekey bundle.
class _OnboardingScreen extends StatefulWidget {
  const _OnboardingScreen();

  @override
  State<_OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<_OnboardingScreen> {
  final _idController = TextEditingController();
  bool _loading = false;
  String? _error;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0D1117),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Logo
              Center(
                child: Container(
                  width: 96,
                  height: 96,
                  decoration: BoxDecoration(
                    gradient: const LinearGradient(
                      colors: [Color(0xFF00D084), Color(0xFF0066FF)],
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                    ),
                    borderRadius: BorderRadius.circular(24),
                    boxShadow: [
                      BoxShadow(
                        color: const Color(0xFF00D084).withOpacity(0.4),
                        blurRadius: 32,
                        spreadRadius: 8,
                      ),
                    ],
                  ),
                  child: const Icon(Icons.shield, color: Colors.white, size: 48),
                ),
              ),
              const SizedBox(height: 32),
              const Text(
                'PARDA',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 32,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 6,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                'Privacy-Assured Resilient Defense Architecture',
                textAlign: TextAlign.center,
                style: TextStyle(color: Colors.grey.shade500, fontSize: 13),
              ),
              const SizedBox(height: 48),
              const Text(
                'Choose a User ID',
                style: TextStyle(color: Colors.white, fontWeight: FontWeight.w600),
              ),
              const SizedBox(height: 8),
              TextField(
                controller: _idController,
                style: const TextStyle(color: Colors.white),
                decoration: InputDecoration(
                  hintText: 'e.g. alpha-1, bravo-7',
                  hintStyle: TextStyle(color: Colors.grey.shade600),
                  filled: true,
                  fillColor: const Color(0xFF161B22),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide: const BorderSide(color: Color(0xFF30363D)),
                  ),
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide: const BorderSide(color: Color(0xFF30363D)),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide: const BorderSide(color: Color(0xFF00D084)),
                  ),
                ),
              ),
              if (_error != null) ...[
                const SizedBox(height: 8),
                Text(_error!, style: const TextStyle(color: Color(0xFFDA3633), fontSize: 13)),
              ],
              const SizedBox(height: 24),
              ElevatedButton(
                onPressed: _loading ? null : _enroll,
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF00D084),
                  foregroundColor: Colors.black,
                  padding: const EdgeInsets.symmetric(vertical: 16),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                ),
                child: _loading
                    ? const SizedBox(
                        height: 20,
                        width: 20,
                        child: CircularProgressIndicator(
                            strokeWidth: 2, color: Colors.black),
                      )
                    : const Text(
                        'Generate Keys & Enroll',
                        style: TextStyle(fontWeight: FontWeight.w700, fontSize: 16),
                      ),
              ),
              const SizedBox(height: 24),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: const Color(0xFF161B22),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: const Color(0xFF30363D)),
                ),
                child: Text(
                  '🔐  Keys generated on-device and stored in hardware security module.\n'
                  '⚠️  Research prototype — not for operational deployment.',
                  style: TextStyle(color: Colors.grey.shade500, fontSize: 11),
                  textAlign: TextAlign.center,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Future<void> _enroll() async {
    final id = _idController.text.trim();
    if (id.isEmpty) {
      setState(() => _error = 'Please enter a user ID');
      return;
    }
    setState(() { _loading = true; _error = null; });
    try {
      await context.read<SessionService>().enroll(userId: id);
    } catch (e) {
      setState(() => _error = 'Enrollment failed: $e');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }
}
