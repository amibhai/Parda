import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../config/app_config.dart';
import '../services/session_service.dart';
import '../theme/app_theme.dart';

/// Relay configuration, mesh control, identity management, and an
/// honest summary of what this build does and does not guarantee.
class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late final TextEditingController _relayController =
      TextEditingController(text: AppConfig.relayBaseUrl);
  bool _savingRelay = false;
  bool _busyMesh = false;

  @override
  void dispose() {
    _relayController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final session = context.watch<SessionService>();

    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 40),
        children: [
          const _SectionHeader('Identity'),
          _Card(
            children: [
              _InfoRow(
                icon: Icons.badge_outlined,
                label: 'User ID',
                value: session.localUserId ?? '—',
              ),
              const Divider(height: 20),
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: const Icon(Icons.cloud_upload_outlined, size: 20),
                title: const Text('Re-publish keys', style: TextStyle(fontSize: 14.5)),
                subtitle: const Text(
                  'Upload this device\'s prekey bundle again — needed if the '
                  'relay was reset while your identity here is still valid.',
                  style: TextStyle(fontSize: 12, height: 1.4),
                ),
                onTap: () => _republish(session),
              ),
            ],
          ),

          const SizedBox(height: 22),
          const _SectionHeader('Relay server'),
          _Card(
            children: [
              TextField(
                controller: _relayController,
                autocorrect: false,
                enableSuggestions: false,
                keyboardType: TextInputType.url,
                style: const TextStyle(color: AppColors.textPrimary, fontSize: 14),
                decoration: const InputDecoration(
                  prefixIcon: Icon(Icons.dns_outlined, size: 20),
                  hintText: 'http://127.0.0.1:8080',
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
              const SizedBox(height: 14),
              Row(
                children: [
                  Expanded(
                    child: ElevatedButton(
                      onPressed: _savingRelay ? null : () => _saveRelay(session),
                      child: _savingRelay
                          ? const SizedBox(
                              height: 18,
                              width: 18,
                              child: CircularProgressIndicator(
                                  strokeWidth: 2, color: Colors.black),
                            )
                          : const Text('Save & test'),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              _relayStatusLine(session),
            ],
          ),

          const SizedBox(height: 22),
          const _SectionHeader('Offline mesh'),
          _Card(
            children: [
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                value: session.meshRunning,
                activeThumbColor: AppColors.secure,
                title: const Text('Mesh mode', style: TextStyle(fontSize: 14.5)),
                subtitle: const Text(
                  'Relay messages device-to-device over Bluetooth LE when no '
                  'network is available.',
                  style: TextStyle(fontSize: 12, height: 1.4),
                ),
                onChanged: _busyMesh ? null : (v) => _toggleMesh(session, v),
              ),
              const Divider(height: 20),
              const _Caveat(
                'Mesh mode has never been verified between two devices. It '
                'advertises and scans over real Bluetooth, but a completed '
                'peer-to-peer exchange has not been observed. It may simply '
                'find nothing.',
              ),
            ],
          ),

          const SizedBox(height: 22),
          const _SectionHeader('This build'),
          const _Card(
            children: [
              _InfoRow(
                icon: Icons.lock_outline,
                label: 'Encryption',
                value: 'Signal Protocol (X3DH + Double Ratchet)',
              ),
              Divider(height: 20),
              _InfoRow(
                icon: Icons.storage_outlined,
                label: 'Key storage',
                value: 'Encrypted prefs, Keystore master key',
              ),
              Divider(height: 20),
              _Caveat(
                'The Curve25519 private key is not held inside the Android '
                'Keystore — Android exposes no X25519 primitive the Double '
                'Ratchet could use. What the Keystore protects is the key '
                'that encrypts this store at rest.',
              ),
              Divider(height: 20),
              _Caveat(
                'Sealed sender, mix routing, and self-destruct are '
                'implemented in the Rust workspace but are not wired into '
                'this Android client. Messages here go directly to the '
                'relay, which therefore sees who is talking to whom.',
              ),
              Divider(height: 20),
              _Caveat(
                'Research prototype. No third-party audit. Not for '
                'operational use.',
                color: AppColors.warning,
              ),
            ],
          ),

          const SizedBox(height: 22),
          const _SectionHeader('Danger zone'),
          _Card(
            borderColor: AppColors.danger.withValues(alpha: 0.45),
            children: [
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: const Icon(Icons.delete_forever_outlined,
                    size: 20, color: AppColors.danger),
                title: const Text(
                  'Erase identity',
                  style: TextStyle(fontSize: 14.5, color: AppColors.danger),
                ),
                subtitle: const Text(
                  'Deletes this device\'s keys, sessions and messages. '
                  'Conversations cannot be recovered.',
                  style: TextStyle(fontSize: 12, height: 1.4),
                ),
                onTap: () => _confirmWipe(session),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _relayStatusLine(SessionService session) {
    final (icon, text, color) = switch (session.relayStatus) {
      RelayStatus.online => (Icons.check_circle_outline, 'Reachable', AppColors.secure),
      RelayStatus.offline => (Icons.error_outline, 'Not reachable', AppColors.danger),
      RelayStatus.checking => (Icons.sync, 'Checking…', AppColors.textMuted),
      RelayStatus.unknown => (Icons.help_outline, 'Not tested yet', AppColors.textMuted),
    };
    return Row(
      children: [
        Icon(icon, size: 15, color: color),
        const SizedBox(width: 8),
        Text(text, style: TextStyle(color: color, fontSize: 12.5)),
      ],
    );
  }

  Widget _preset(String label, String url) => ActionChip(
        label: Text(label, style: const TextStyle(fontSize: 11.5)),
        onPressed: () => setState(() => _relayController.text = url),
        backgroundColor: AppColors.surfaceHigh,
        side: const BorderSide(color: AppColors.border),
        labelStyle: const TextStyle(color: AppColors.textSecondary),
      );

  Future<void> _saveRelay(SessionService session) async {
    setState(() => _savingRelay = true);
    try {
      await session.setRelayUrl(_relayController.text);
      if (!mounted) return;
      final ok = session.relayStatus == RelayStatus.online;
      _toast(ok ? 'Relay reachable' : 'Saved, but the relay did not respond');
    } finally {
      if (mounted) setState(() => _savingRelay = false);
    }
  }

  Future<void> _republish(SessionService session) async {
    try {
      await session.republishBundle();
      if (mounted) _toast('Keys published');
    } catch (e) {
      if (mounted) _toast('Could not publish: $e');
    }
  }

  Future<void> _toggleMesh(SessionService session, bool value) async {
    setState(() => _busyMesh = true);
    try {
      final problem = await session.setMeshEnabled(value);
      if (problem != null && mounted) _toast(problem);
    } finally {
      if (mounted) setState(() => _busyMesh = false);
    }
  }

  Future<void> _confirmWipe(SessionService session) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Erase identity?'),
        content: const Text(
          'Your keys, sessions and messages on this device will be deleted. '
          'This cannot be undone, and existing conversations will not be '
          'recoverable even if you re-enroll with the same user ID.',
          style: TextStyle(fontSize: 13.5, height: 1.45),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            style: TextButton.styleFrom(foregroundColor: AppColors.danger),
            child: const Text('Erase'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await session.wipeIdentity();
    if (mounted) {
      // Popping back to the root lets _AppRoot re-evaluate and show
      // onboarding, rather than leaving a dead Settings screen over a
      // now-identity-less app.
      Navigator.of(context).popUntil((route) => route.isFirst);
    }
  }

  void _toast(String message) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
  }
}

// ─── Small presentational pieces ─────────────────────────────────────────────

class _SectionHeader extends StatelessWidget {
  final String text;
  const _SectionHeader(this.text);

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(left: 4, bottom: 8),
        child: Text(
          text.toUpperCase(),
          style: const TextStyle(
            color: AppColors.textMuted,
            fontSize: 11,
            fontWeight: FontWeight.w700,
            letterSpacing: 1.2,
          ),
        ),
      );
}

class _Card extends StatelessWidget {
  final List<Widget> children;
  final Color? borderColor;
  const _Card({required this.children, this.borderColor});

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: AppColors.surface,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: borderColor ?? AppColors.border),
        ),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: children),
      );
}

class _InfoRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;
  const _InfoRow({required this.icon, required this.label, required this.value});

  @override
  Widget build(BuildContext context) => Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, size: 18, color: AppColors.textSecondary),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(label,
                    style: const TextStyle(color: AppColors.textMuted, fontSize: 11.5)),
                const SizedBox(height: 3),
                Text(value,
                    style: const TextStyle(
                        color: AppColors.textPrimary, fontSize: 14, height: 1.35)),
              ],
            ),
          ),
        ],
      );
}

/// A documented limitation shown to the user rather than buried in the
/// README — the app should not imply guarantees it does not provide.
class _Caveat extends StatelessWidget {
  final String text;
  final Color color;
  const _Caveat(this.text, {this.color = AppColors.textMuted});

  @override
  Widget build(BuildContext context) => Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.info_outline, size: 15, color: color),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              text,
              style: TextStyle(color: color, fontSize: 12, height: 1.45),
            ),
          ),
        ],
      );
}
