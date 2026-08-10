import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:provider/provider.dart';

import '../models/contact_card.dart';
import '../services/session_service.dart';
import '../theme/app_theme.dart';
import 'chat_screen.dart';

/// Scans another device's contact card and opens a verified session.
class ScanScreen extends StatefulWidget {
  const ScanScreen({super.key});

  @override
  State<ScanScreen> createState() => _ScanScreenState();
}

class _ScanScreenState extends State<ScanScreen> {
  final MobileScannerController _controller = MobileScannerController(
    detectionSpeed: DetectionSpeed.noDuplicates,
    formats: const [BarcodeFormat.qrCode],
  );

  /// Guards against the detector firing again while the import dialog is
  /// up. Without it a code held in frame produces a stack of duplicate
  /// prompts.
  bool _handling = false;
  String? _error;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _onDetect(BarcodeCapture capture) async {
    if (_handling) return;
    final raw = capture.barcodes
        .map((b) => b.rawValue)
        .firstWhere((v) => v != null && v.isNotEmpty, orElse: () => null);
    if (raw == null) return;

    final card = ContactCard.tryParse(raw);
    if (card == null) {
      // A camera pointed at the world finds plenty of QR codes that are
      // not contact cards. Say so once, quietly, and keep scanning.
      if (mounted) setState(() => _error = 'That is not a PARDA contact code.');
      return;
    }

    setState(() {
      _handling = true;
      _error = null;
    });
    await _controller.stop();
    if (!mounted) return;
    await _confirm(card);
  }

  Future<void> _confirm(ContactCard card) async {
    final session = context.read<SessionService>();
    final differentRelay = card.relayUrl != null &&
        card.relayUrl!.isNotEmpty &&
        card.relayUrl != session.relayBaseUrl;

    var adoptRelay = differentRelay;

    final confirmed = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDialogState) => AlertDialog(
          title: const Text('Add contact'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                card.userId,
                style: const TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 18,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(height: 10),
              const Text(
                'Key fingerprint',
                style: TextStyle(color: AppColors.textMuted, fontSize: 11.5),
              ),
              const SizedBox(height: 3),
              Text(
                card.shortIdentityFingerprint,
                style: const TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 14,
                  fontFamily: 'monospace',
                  letterSpacing: 1.4,
                ),
              ),
              const SizedBox(height: 14),
              const Text(
                'Check this matches what their screen shows. Because you '
                'scanned it in person, their key never passed through the '
                'relay — this contact will be marked verified.',
                style: TextStyle(
                    color: AppColors.textMuted, fontSize: 12.5, height: 1.45),
              ),
              if (differentRelay) ...[
                const SizedBox(height: 12),
                CheckboxListTile(
                  contentPadding: EdgeInsets.zero,
                  dense: true,
                  value: adoptRelay,
                  activeColor: AppColors.secure,
                  onChanged: (v) => setDialogState(() => adoptRelay = v ?? false),
                  title: const Text(
                    'Use their relay',
                    style: TextStyle(color: AppColors.textPrimary, fontSize: 13.5),
                  ),
                  subtitle: Text(
                    card.relayUrl!,
                    style: const TextStyle(color: AppColors.textMuted, fontSize: 11.5),
                  ),
                ),
                const Text(
                  'You both need the same relay to exchange messages.',
                  style: TextStyle(color: AppColors.warning, fontSize: 11.5, height: 1.4),
                ),
              ],
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(false),
              child: const Text('Cancel'),
            ),
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(true),
              child: const Text('Add'),
            ),
          ],
        ),
      ),
    );

    if (confirmed != true) {
      if (mounted) {
        setState(() => _handling = false);
        await _controller.start();
      }
      return;
    }

    try {
      final peer = await session.importContact(card, adoptRelay: adoptRelay);
      if (!mounted) return;
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(builder: (_) => ChatScreen(remoteUserId: peer)),
      );
    } on PlatformException catch (e) {
      if (!mounted) return;
      setState(() {
        _handling = false;
        _error = _friendly(e);
      });
      await _controller.start();
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _handling = false;
        _error = 'Could not add this contact: $e';
      });
      await _controller.start();
    }
  }

  String _friendly(PlatformException e) => switch (e.code) {
        // The one failure that matters: a card contradicting a key the
        // user already confirmed in person is either an impersonation
        // attempt or a genuine reinstall, and the app cannot tell which.
        'IDENTITY_CHANGED' => e.message ??
            'This code carries a different key than the one you verified before.',
        'SELF_CARD' => 'That is your own code.',
        _ => e.message ?? 'Could not add this contact.',
      };

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Scan their code')),
      body: Column(
        children: [
          Expanded(
            child: Stack(
              fit: StackFit.expand,
              children: [
                MobileScanner(
                  controller: _controller,
                  onDetect: _onDetect,
                  errorBuilder: (context, error) => _cameraError(error),
                ),
                // A viewfinder, so it is obvious where to aim.
                IgnorePointer(
                  child: Center(
                    child: Container(
                      width: 240,
                      height: 240,
                      decoration: BoxDecoration(
                        border: Border.all(color: AppColors.secure, width: 2),
                        borderRadius: BorderRadius.circular(20),
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
          Container(
            width: double.infinity,
            color: AppColors.surface,
            padding: const EdgeInsets.fromLTRB(20, 16, 20, 24),
            child: SafeArea(
              top: false,
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (_error != null) ...[
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: AppColors.danger.withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(10),
                        border:
                            Border.all(color: AppColors.danger.withValues(alpha: 0.4)),
                      ),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Icon(Icons.error_outline,
                              color: AppColors.danger, size: 18),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Text(
                              _error!,
                              style: const TextStyle(
                                  color: AppColors.danger,
                                  fontSize: 12.5,
                                  height: 1.4),
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 14),
                  ],
                  const Text(
                    'Point the camera at their PARDA code',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                        color: AppColors.textSecondary, fontSize: 13.5),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  /// Camera failures are almost always a denied permission, and the
  /// scanner cannot recover from that on its own — send the user to the
  /// place where it can be fixed rather than leaving a black rectangle.
  Widget _cameraError(MobileScannerException error) => ColoredBox(
        color: AppColors.bg,
        child: Center(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 32),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Icon(Icons.no_photography_outlined,
                    size: 44, color: AppColors.textMuted),
                const SizedBox(height: 16),
                const Text(
                  'Camera unavailable',
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  error.errorCode == MobileScannerErrorCode.permissionDenied
                      ? 'PARDA needs camera access to scan a contact code. '
                          'Grant it in Android settings, then come back.'
                      : 'The camera could not be started: ${error.errorCode.name}',
                  textAlign: TextAlign.center,
                  style: const TextStyle(
                      color: AppColors.textMuted, fontSize: 12.5, height: 1.5),
                ),
              ],
            ),
          ),
        ),
      );
}
