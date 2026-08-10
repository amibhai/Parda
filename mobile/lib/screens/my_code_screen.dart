import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../models/contact_card.dart';
import '../services/session_service.dart';
import '../theme/app_theme.dart';
import 'scan_screen.dart';

/// Shows this device's contact card as a QR code for someone standing
/// next to you to scan.
///
/// This is the security-relevant half of setup, not a shortcut: keys
/// exchanged this way never pass through the relay, so a malicious relay
/// cannot substitute one. See [ContactCard] for why that matters.
class MyCodeScreen extends StatefulWidget {
  const MyCodeScreen({super.key});

  @override
  State<MyCodeScreen> createState() => _MyCodeScreenState();
}

class _MyCodeScreenState extends State<MyCodeScreen> {
  ContactCard? _card;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final card = await context.read<SessionService>().contactCard();
      if (mounted) setState(() => _card = card);
    } catch (e) {
      if (mounted) setState(() => _error = 'Could not build your contact card: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    final session = context.watch<SessionService>();

    return Scaffold(
      appBar: AppBar(title: const Text('My code')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(20, 16, 20, 40),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              session.localUserId ?? '',
              textAlign: TextAlign.center,
              style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 20,
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: 4),
            const Text(
              'Have them scan this to add you',
              textAlign: TextAlign.center,
              style: TextStyle(color: AppColors.textSecondary, fontSize: 13),
            ),
            const SizedBox(height: 24),

            if (_error != null)
              _errorBox(_error!)
            else if (_card == null)
              const SizedBox(
                height: 300,
                child: Center(child: CircularProgressIndicator()),
              )
            else
              _qr(_card!),

            const SizedBox(height: 28),
            ElevatedButton.icon(
              onPressed: () => Navigator.of(context).pushReplacement(
                MaterialPageRoute(builder: (_) => const ScanScreen()),
              ),
              icon: const Icon(Icons.qr_code_scanner, size: 20),
              label: const Text('Scan their code instead'),
            ),

            const SizedBox(height: 24),
            _panel(
              icon: Icons.verified_user_outlined,
              color: AppColors.secure,
              title: 'Why scanning is safer',
              body: 'Keys exchanged by scanning never pass through the relay, '
                  'so a compromised relay cannot substitute its own and read '
                  'your messages. Adding someone by typing their user ID '
                  'trusts the relay to hand over the right key.',
            ),
            const SizedBox(height: 12),
            _panel(
              icon: Icons.screen_share_outlined,
              title: 'What is in this code',
              body: 'Your user ID, your public keys, and the relay address '
                  'you are using. No private key material — this code is safe '
                  'to show to whoever you want to talk to, and useless to '
                  'anyone impersonating you.',
            ),
          ],
        ),
      ),
    );
  }

  Widget _qr(ContactCard card) => Column(
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              // A white quiet zone is not decoration — scanners rely on
              // the light/dark contrast, and this app's dark surfaces
              // would otherwise make the code unreadable.
              color: Colors.white,
              borderRadius: BorderRadius.circular(16),
            ),
            child: QrImageView(
              data: card.encode(),
              version: QrVersions.auto,
              size: 260,
              backgroundColor: Colors.white,
              // A contact card is long; medium correction keeps the
              // module count low enough to scan comfortably while still
              // tolerating glare and camera shake.
              errorCorrectionLevel: QrErrorCorrectLevel.M,
            ),
          ),
          const SizedBox(height: 16),
          const Text(
            'Key fingerprint',
            style: TextStyle(color: AppColors.textMuted, fontSize: 11.5),
          ),
          const SizedBox(height: 4),
          Text(
            card.shortIdentityFingerprint,
            style: const TextStyle(
              color: AppColors.textSecondary,
              fontSize: 15,
              fontFamily: 'monospace',
              letterSpacing: 1.5,
            ),
          ),
        ],
      );

  Widget _errorBox(String message) => Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: AppColors.danger.withValues(alpha: 0.12),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: AppColors.danger.withValues(alpha: 0.4)),
        ),
        child: Text(
          message,
          style: const TextStyle(color: AppColors.danger, fontSize: 12.5, height: 1.45),
        ),
      );

  Widget _panel({
    required IconData icon,
    required String title,
    required String body,
    Color color = AppColors.textSecondary,
  }) =>
      Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: AppColors.surface,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: AppColors.border),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(icon, size: 17, color: color),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: TextStyle(
                      color: color == AppColors.textSecondary
                          ? AppColors.textPrimary
                          : color,
                      fontSize: 13.5,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 5),
                  Text(
                    body,
                    style: const TextStyle(
                      color: AppColors.textMuted,
                      fontSize: 12.5,
                      height: 1.45,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      );
}
