import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../config/app_config.dart';
import '../services/session_service.dart';
import '../theme/app_theme.dart';

/// First-run enrollment: pick an ID, point at a relay, generate keys.
///
/// The relay field lives here rather than only in Settings because
/// enrollment *publishes* to the relay — a user who cannot reach one at
/// this moment needs to know that now, not after a failed first send.
class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  final _idController = TextEditingController();
  final _relayController = TextEditingController(text: AppConfig.relayBaseUrl);
  bool _loading = false;
  String? _error;

  @override
  void dispose() {
    _idController.dispose();
    _relayController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(24, 40, 24, 32),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Center(child: BrandMark(size: 88, glow: true)),
              const SizedBox(height: 28),
              const Text(
                'PARDA',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 30,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 7,
                ),
              ),
              const SizedBox(height: 6),
              const Text(
                'Privacy-Assured Resilient\nDefense Architecture',
                textAlign: TextAlign.center,
                style: TextStyle(color: AppColors.textSecondary, fontSize: 13, height: 1.4),
              ),
              const SizedBox(height: 40),

              _label('Your user ID'),
              const SizedBox(height: 8),
              TextField(
                controller: _idController,
                autocorrect: false,
                enableSuggestions: false,
                textInputAction: TextInputAction.next,
                style: const TextStyle(color: AppColors.textPrimary),
                decoration: const InputDecoration(
                  hintText: 'e.g. alpha-1',
                  prefixIcon: Icon(Icons.person_outline, size: 20),
                ),
              ),
              const SizedBox(height: 6),
              const Text(
                'How others address you on this relay. Pick something short; '
                'it is visible to the relay operator.',
                style: TextStyle(color: AppColors.textMuted, fontSize: 12, height: 1.4),
              ),

              const SizedBox(height: 24),
              _label('Relay server'),
              const SizedBox(height: 8),
              TextField(
                controller: _relayController,
                autocorrect: false,
                enableSuggestions: false,
                keyboardType: TextInputType.url,
                style: const TextStyle(color: AppColors.textPrimary, fontSize: 14),
                decoration: const InputDecoration(
                  hintText: 'http://127.0.0.1:8080',
                  prefixIcon: Icon(Icons.dns_outlined, size: 20),
                ),
              ),
              const SizedBox(height: 10),
              Wrap(
                spacing: 8,
                children: [
                  _preset('Local (adb reverse)', AppConfig.defaultRelayUrl),
                  _preset('Android emulator', AppConfig.emulatorRelayUrl),
                ],
              ),

              if (_error != null) ...[
                const SizedBox(height: 18),
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: AppColors.danger.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: AppColors.danger.withValues(alpha: 0.4)),
                  ),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Icon(Icons.error_outline, color: AppColors.danger, size: 18),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Text(
                          _error!,
                          style: const TextStyle(
                              color: AppColors.danger, fontSize: 12.5, height: 1.4),
                        ),
                      ),
                    ],
                  ),
                ),
              ],

              const SizedBox(height: 28),
              ElevatedButton(
                onPressed: _loading ? null : _enroll,
                child: _loading
                    ? const SizedBox(
                        height: 20,
                        width: 20,
                        child: CircularProgressIndicator(strokeWidth: 2, color: Colors.black),
                      )
                    : const Text('Generate keys & enroll'),
              ),

              const SizedBox(height: 24),
              Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: AppColors.surface,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: AppColors.border),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _bullet(
                      Icons.key_outlined,
                      'Keys are generated on this device and stored encrypted '
                      'under an Android Keystore master key.',
                    ),
                    const SizedBox(height: 10),
                    _bullet(
                      Icons.science_outlined,
                      'Research prototype. Not audited, not for operational use.',
                      color: AppColors.warning,
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _label(String text) => Text(
        text,
        style: const TextStyle(
          color: AppColors.textPrimary,
          fontWeight: FontWeight.w600,
          fontSize: 14,
        ),
      );

  Widget _bullet(IconData icon, String text, {Color color = AppColors.textSecondary}) => Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, size: 15, color: color),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              text,
              style: TextStyle(color: color, fontSize: 12, height: 1.45),
            ),
          ),
        ],
      );

  Widget _preset(String label, String url) => ActionChip(
        label: Text(label, style: const TextStyle(fontSize: 11.5)),
        onPressed: () => setState(() => _relayController.text = url),
        backgroundColor: AppColors.surfaceHigh,
        side: const BorderSide(color: AppColors.border),
        labelStyle: const TextStyle(color: AppColors.textSecondary),
      );

  Future<void> _enroll() async {
    final id = _idController.text.trim();
    if (id.isEmpty) {
      setState(() => _error = 'Enter a user ID.');
      return;
    }
    // The ID goes into URL paths on the relay; rejecting the awkward
    // characters here gives a clear message instead of an opaque 404 later.
    if (!RegExp(r'^[A-Za-z0-9._-]{1,64}$').hasMatch(id)) {
      setState(() => _error =
          'Use only letters, digits, dot, dash or underscore (max 64 characters).');
      return;
    }

    setState(() {
      _loading = true;
      _error = null;
    });

    final session = context.read<SessionService>();
    try {
      await session.setRelayUrl(_relayController.text);
      await session.enroll(id);
    } catch (e) {
      if (mounted) {
        setState(() => _error = _friendlyError(e));
      }
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  /// Enrollment fails most often because the relay is unreachable, and
  /// the raw exception ("SocketException: ... errno = 111") tells a user
  /// nothing actionable. The identity itself is already generated and
  /// persisted at that point, so the message says what actually happened.
  String _friendlyError(Object e) {
    final text = e.toString();
    if (text.contains('SocketException') ||
        text.contains('TimeoutException') ||
        text.contains('Connection refused')) {
      return 'Your keys were created, but the relay at '
          '${_relayController.text.trim()} could not be reached. '
          'Check the address and that the relay is running, then retry '
          'publishing from Settings.';
    }
    return text;
  }
}
