import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../services/session_service.dart';
import '../theme/app_theme.dart';

/// Out-of-band identity verification (Sub-Phase 4.5D).
///
/// Displays the 60-digit safety number for a conversation, computed by
/// `SignalPlugin.safetyNumber` and byte-compatible with
/// `protocol/src/trust.rs`'s `Fingerprint`. Until this screen existed
/// the fingerprint mechanism was implemented and tested but reachable
/// only from code — there was no way for a human to actually compare
/// one, which is the entire point of a safety number.
///
/// ## Comparison *and* enforcement
///
/// Confirming here records the peer's current identity key. From then
/// on a bundle carrying a different key for them — fetched from the
/// relay or scanned — is refused rather than silently re-pinned, which
/// is what makes the comparison worth doing. Scanning a contact card in
/// person achieves the same thing without the manual step.
class SafetyNumberScreen extends StatefulWidget {
  final String remoteUserId;

  const SafetyNumberScreen({super.key, required this.remoteUserId});

  @override
  State<SafetyNumberScreen> createState() => _SafetyNumberScreenState();
}

class _SafetyNumberScreenState extends State<SafetyNumberScreen> {
  String? _digits;
  String? _error;
  bool _verified = false;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _load();
    _refreshVerified();
  }

  Future<void> _refreshVerified() async {
    final verified =
        await context.read<SessionService>().isVerified(widget.remoteUserId);
    if (mounted) setState(() => _verified = verified);
  }

  Future<void> _setVerified(bool value) async {
    setState(() => _busy = true);
    final session = context.read<SessionService>();
    try {
      if (value) {
        await session.markVerified(widget.remoteUserId);
      } else {
        await session.forgetVerification(widget.remoteUserId);
      }
      await _refreshVerified();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(value
                ? 'Marked verified. A different key for this contact will now be refused.'
                : 'Verification removed. This contact is back to trust-on-first-use.'),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Could not update verification: $e')),
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _load() async {
    try {
      final digits =
          await context.read<SessionService>().safetyNumber(widget.remoteUserId);
      if (mounted) setState(() => _digits = digits);
    } catch (e) {
      if (mounted) {
        setState(() => _error = e.toString().contains('NO_IDENTITY')
            ? 'No key on file for ${widget.remoteUserId} yet. Send or receive '
                'a message first, then come back.'
            : 'Could not compute the safety number: $e');
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Safety number')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(20, 20, 20, 40),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'You and ${widget.remoteUserId}',
              textAlign: TextAlign.center,
              style: const TextStyle(
                color: AppColors.textSecondary,
                fontSize: 13.5,
              ),
            ),
            const SizedBox(height: 20),
            if (_error != null)
              _errorBox(_error!)
            else if (_digits == null)
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 60),
                child: Center(child: CircularProgressIndicator()),
              )
            else
              _digitGrid(_digits!),

            if (_digits != null) ...[
              const SizedBox(height: 16),
              Center(
                child: TextButton.icon(
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: _digits!));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Safety number copied')),
                    );
                  },
                  icon: const Icon(Icons.copy, size: 16),
                  label: const Text('Copy'),
                ),
              ),
            ],

            if (_digits != null) ...[
              const SizedBox(height: 20),
              _verifyControl(),
            ],

            const SizedBox(height: 24),
            _panel(
              icon: Icons.compare_arrows,
              title: 'How to verify',
              body: 'Compare these 60 digits with ${widget.remoteUserId} over a '
                  'channel you already trust — in person is best. If both '
                  'devices show the same number, no one substituted keys when '
                  'this conversation started.',
            ),
            const SizedBox(height: 12),
            _panel(
              icon: Icons.warning_amber_outlined,
              color: AppColors.warning,
              title: 'What verifying cannot undo',
              body: 'If someone was already impersonating this contact when '
                  'the conversation started, verifying now confirms the '
                  'impostor\'s key rather than the real one. Verification '
                  'protects everything after it, never what came before — '
                  'which is why scanning a code in person at the start is '
                  'stronger than comparing numbers later.',
            ),
            const SizedBox(height: 12),
            _panel(
              icon: Icons.info_outline,
              title: 'About this number',
              body: 'Derived with HKDF-SHA256 over both identity keys. '
                  'Inspired by Signal\'s safety numbers and deliberately not '
                  'bit-compatible with them — compare PARDA numbers only '
                  'against other PARDA numbers.',
            ),
          ],
        ),
      ),
    );
  }

  /// The action that turns a comparison into an enforced decision.
  Widget _verifyControl() {
    if (_verified) {
      return Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: AppColors.secure.withValues(alpha: 0.10),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: AppColors.secure.withValues(alpha: 0.4)),
        ),
        child: Row(
          children: [
            const Icon(Icons.verified_user, color: AppColors.secure, size: 18),
            const SizedBox(width: 10),
            const Expanded(
              child: Text(
                'Verified. A different key for this contact will be refused.',
                style: TextStyle(
                    color: AppColors.secure, fontSize: 12.5, height: 1.4),
              ),
            ),
            TextButton(
              onPressed: _busy ? null : () => _setVerified(false),
              style: TextButton.styleFrom(foregroundColor: AppColors.textMuted),
              child: const Text('Remove', style: TextStyle(fontSize: 12.5)),
            ),
          ],
        ),
      );
    }
    return ElevatedButton.icon(
      onPressed: _busy ? null : () => _setVerified(true),
      icon: const Icon(Icons.check_circle_outline, size: 19),
      label: const Text('These numbers match'),
    );
  }

  /// Twelve groups of five digits in a 3-column grid — the layout users
  /// are used to from Signal, and far easier to read aloud accurately
  /// than one 60-character run.
  Widget _digitGrid(String digits) {
    final groups = digits.split(' ');
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 22, horizontal: 12),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppColors.border),
      ),
      child: Wrap(
        alignment: WrapAlignment.center,
        spacing: 22,
        runSpacing: 14,
        children: [
          for (final g in groups)
            SizedBox(
              width: 74,
              child: Text(
                g,
                textAlign: TextAlign.center,
                style: const TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 20,
                  fontFamily: 'monospace',
                  fontWeight: FontWeight.w600,
                  letterSpacing: 1.5,
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _errorBox(String message) => Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: AppColors.danger.withValues(alpha: 0.12),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: AppColors.danger.withValues(alpha: 0.4)),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Icon(Icons.error_outline, color: AppColors.danger, size: 18),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                message,
                style: const TextStyle(
                    color: AppColors.danger, fontSize: 12.5, height: 1.45),
              ),
            ),
          ],
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
