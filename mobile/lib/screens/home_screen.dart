import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../models/message.dart';
import '../services/session_service.dart';
import '../theme/app_theme.dart';
import 'chat_screen.dart';
import 'my_code_screen.dart';
import 'scan_screen.dart';
import 'settings_screen.dart';

/// Conversation list, plus the app's connectivity and mesh status.
class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final session = context.watch<SessionService>();
    final conversations = session.conversations;

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 16,
        title: Row(
          children: [
            const BrandMark(size: 30),
            const SizedBox(width: 12),
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Text(
                  'PARDA',
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontWeight: FontWeight.w700,
                    fontSize: 17,
                    letterSpacing: 2.5,
                  ),
                ),
                Text(
                  session.localUserId ?? '',
                  style: const TextStyle(color: AppColors.textMuted, fontSize: 11),
                ),
              ],
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.qr_code_2),
            tooltip: 'My code',
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const MyCodeScreen()),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.settings_outlined),
            tooltip: 'Settings',
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const SettingsScreen()),
            ),
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(37),
          child: _StatusBar(session: session),
        ),
      ),
      body: Column(
        children: [
          if (session.lastError != null) _ErrorBanner(session: session),
          Expanded(child: _buildList(context, session, conversations)),
        ],
      ),
      // Scanning is the primary action, not the typed-ID path: it is
      // both easier and the only one that keeps the relay out of key
      // exchange. Adding by ID remains available inside the sheet.
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () => _showNewChatSheet(context),
        backgroundColor: AppColors.secure,
        foregroundColor: Colors.black,
        icon: const Icon(Icons.qr_code_scanner),
        label: const Text('Add contact', style: TextStyle(fontWeight: FontWeight.w700)),
      ),
    );
  }

  Widget _buildList(
    BuildContext context,
    SessionService session,
    List<String> conversations,
  ) {
    return RefreshIndicator(
        color: AppColors.secure,
        backgroundColor: AppColors.surface,
        onRefresh: () async {
          await session.refreshRelayStatus();
          await session.pollNow();
        },
        child: conversations.isEmpty
            ? const _EmptyState()
            : ListView.separated(
                physics: const AlwaysScrollableScrollPhysics(),
                itemCount: conversations.length,
                separatorBuilder: (_, __) => const Divider(indent: 76),
                itemBuilder: (context, i) {
                  final peer = conversations[i];
                  final msgs = session.messagesFor(peer);
                  return _ConversationTile(
                    peer: peer,
                    lastMessage: msgs.isNotEmpty ? msgs.last : null,
                    onTap: () => Navigator.of(context).push(
                      MaterialPageRoute(builder: (_) => ChatScreen(remoteUserId: peer)),
                    ),
                  );
                },
              ),
    );
  }
}

/// Surfaces a receive failure. Without this a message that arrived and
/// could not be decrypted disappeared entirely — the relay had already
/// dropped it, so there was nothing left to notice.
class _ErrorBanner extends StatelessWidget {
  final SessionService session;
  const _ErrorBanner({required this.session});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      color: AppColors.danger.withValues(alpha: 0.14),
      padding: const EdgeInsets.fromLTRB(16, 10, 8, 10),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Icon(Icons.warning_amber_outlined, color: AppColors.danger, size: 18),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              session.lastError!,
              style: const TextStyle(
                  color: AppColors.danger, fontSize: 12.5, height: 1.4),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.close, size: 18, color: AppColors.danger),
            visualDensity: VisualDensity.compact,
            onPressed: session.clearError,
            tooltip: 'Dismiss',
          ),
        ],
      ),
    );
  }
}

/// Relay reachability and mesh state. Always visible, because both
/// materially change whether a message can actually be delivered.
class _StatusBar extends StatelessWidget {
  final SessionService session;
  const _StatusBar({required this.session});

  @override
  Widget build(BuildContext context) {
    final (icon, label, color) = switch (session.relayStatus) {
      RelayStatus.online => (Icons.cloud_done_outlined, 'Relay online', AppColors.secure),
      RelayStatus.offline => (Icons.cloud_off_outlined, 'Relay unreachable', AppColors.danger),
      RelayStatus.checking => (Icons.cloud_sync_outlined, 'Checking relay…', AppColors.textMuted),
      RelayStatus.unknown => (Icons.cloud_outlined, 'Relay status unknown', AppColors.textMuted),
    };

    return Container(
      height: 37,
      padding: const EdgeInsets.symmetric(horizontal: 16),
      decoration: const BoxDecoration(
        color: AppColors.surface,
        border: Border(top: BorderSide(color: AppColors.border)),
      ),
      child: Row(
        children: [
          StatusPill(icon: icon, label: label, color: color),
          const SizedBox(width: 8),
          if (session.meshRunning)
            const StatusPill(
              icon: Icons.bluetooth_searching,
              label: 'Mesh on',
              color: AppColors.accent,
            ),
          const Spacer(),
          if (session.relayStatus == RelayStatus.offline)
            TextButton(
              onPressed: session.refreshRelayStatus,
              style: TextButton.styleFrom(
                padding: const EdgeInsets.symmetric(horizontal: 8),
                minimumSize: Size.zero,
                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              ),
              child: const Text('Retry', style: TextStyle(fontSize: 12)),
            ),
        ],
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) => SingleChildScrollView(
        physics: const AlwaysScrollableScrollPhysics(),
        child: ConstrainedBox(
          constraints: BoxConstraints(minHeight: constraints.maxHeight),
          child: const Padding(
            padding: EdgeInsets.symmetric(horizontal: 40),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                BrandMark(size: 76, glow: true),
                SizedBox(height: 26),
                Text(
                  'No conversations yet',
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 18,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                SizedBox(height: 10),
                Text(
                  'Start one with someone enrolled on the same relay. '
                  'Both of you need to have enrolled before a session can '
                  'be established.',
                  textAlign: TextAlign.center,
                  style: TextStyle(
                      color: AppColors.textSecondary, fontSize: 13.5, height: 1.5),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _ConversationTile extends StatelessWidget {
  final String peer;
  final Message? lastMessage;
  final VoidCallback onTap;

  const _ConversationTile({
    required this.peer,
    required this.lastMessage,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return ListTile(
      onTap: onTap,
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      leading: CircleAvatar(
        radius: 22,
        backgroundColor: AppColors.accent.withValues(alpha: 0.18),
        child: Text(
          peer.isNotEmpty ? peer[0].toUpperCase() : '?',
          style: const TextStyle(
            color: AppColors.accent,
            fontWeight: FontWeight.w700,
            fontSize: 17,
          ),
        ),
      ),
      title: Text(
        peer,
        style: const TextStyle(
          color: AppColors.textPrimary,
          fontWeight: FontWeight.w600,
          fontSize: 15,
        ),
      ),
      subtitle: Padding(
        padding: const EdgeInsets.only(top: 3),
        child: Text(
          // A received message's plaintext lives behind a native handle
          // (Sub-Phase 4.5C). Deliberately not decoded just for a preview
          // line — every extra `renderCopy()` is one more place a Dart
          // String materialises and lingers.
          lastMessage == null
              ? 'No messages yet'
              : (lastMessage!.body ?? 'Encrypted message'),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: const TextStyle(color: AppColors.textMuted, fontSize: 13),
        ),
      ),
      trailing: lastMessage == null
          ? const Icon(Icons.lock_outline, size: 15, color: AppColors.secure)
          : Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Text(
                  DateFormat('HH:mm').format(lastMessage!.timestamp),
                  style: const TextStyle(color: AppColors.textMuted, fontSize: 11),
                ),
                const SizedBox(height: 5),
                const Icon(Icons.lock_outline, size: 13, color: AppColors.secure),
              ],
            ),
    );
  }
}

// ─── New chat ────────────────────────────────────────────────────────────────

void _showNewChatSheet(BuildContext context) {
  showModalBottomSheet<void>(
    context: context,
    isScrollControlled: true,
    builder: (_) => const _NewChatSheet(),
  );
}

class _NewChatSheet extends StatefulWidget {
  const _NewChatSheet();

  @override
  State<_NewChatSheet> createState() => _NewChatSheetState();
}

class _NewChatSheetState extends State<_NewChatSheet> {
  final _controller = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.only(
        left: 24,
        right: 24,
        top: 24,
        bottom: MediaQuery.of(context).viewInsets.bottom + 24,
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Center(
            child: Container(
              width: 36,
              height: 4,
              decoration: BoxDecoration(
                color: AppColors.border,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),
          const SizedBox(height: 20),
          const Text(
            'Add a contact',
            style: TextStyle(
              color: AppColors.textPrimary,
              fontSize: 18,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 16),

          // In-person exchange first, and visibly the recommended one —
          // it is the only path that keeps the relay out of key
          // exchange, so presenting the two as equivalent choices would
          // misrepresent them.
          _PrimaryOption(
            icon: Icons.qr_code_scanner,
            title: 'Scan their code',
            subtitle: 'In person. Their key never touches the relay, and the '
                'contact is marked verified.',
            onTap: () {
              Navigator.of(context).pop();
              Navigator.of(context).push(
                MaterialPageRoute(builder: (_) => const ScanScreen()),
              );
            },
          ),
          const SizedBox(height: 10),
          _PrimaryOption(
            icon: Icons.qr_code_2,
            title: 'Show my code',
            subtitle: 'Let them scan you instead.',
            onTap: () {
              Navigator.of(context).pop();
              Navigator.of(context).push(
                MaterialPageRoute(builder: (_) => const MyCodeScreen()),
              );
            },
          ),

          const SizedBox(height: 22),
          const Row(
            children: [
              Expanded(child: Divider(color: AppColors.border)),
              Padding(
                padding: EdgeInsets.symmetric(horizontal: 12),
                child: Text(
                  'or add by user ID',
                  style: TextStyle(color: AppColors.textMuted, fontSize: 11.5),
                ),
              ),
              Expanded(child: Divider(color: AppColors.border)),
            ],
          ),
          const SizedBox(height: 14),
          const Text(
            'Fetches their key from the relay, which you have to trust to '
            'hand over the right one. Verify the safety number afterwards.',
            style: TextStyle(color: AppColors.textMuted, fontSize: 12, height: 1.45),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _controller,
            autocorrect: false,
            enableSuggestions: false,
            textInputAction: TextInputAction.go,
            onSubmitted: (_) => _start(),
            style: const TextStyle(color: AppColors.textPrimary),
            decoration: const InputDecoration(
              hintText: 'User ID',
              prefixIcon: Icon(Icons.person_search_outlined, size: 20),
            ),
          ),
          if (_error != null) ...[
            const SizedBox(height: 12),
            Text(
              _error!,
              style: const TextStyle(color: AppColors.danger, fontSize: 12.5, height: 1.4),
            ),
          ],
          const SizedBox(height: 20),
          ElevatedButton(
            onPressed: _busy ? null : _start,
            child: _busy
                ? const SizedBox(
                    height: 20,
                    width: 20,
                    child: CircularProgressIndicator(strokeWidth: 2, color: Colors.black),
                  )
                : const Text('Start chat'),
          ),
        ],
      ),
    );
  }

  Future<void> _start() async {
    final peer = _controller.text.trim();
    if (peer.isEmpty) {
      setState(() => _error = 'Enter a user ID.');
      return;
    }
    final session = context.read<SessionService>();
    if (peer == session.localUserId) {
      setState(() => _error = 'That is your own ID.');
      return;
    }

    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await session.startConversation(peer);
      if (!mounted) return;
      Navigator.of(context).pop();
      Navigator.of(context).push(
        MaterialPageRoute(builder: (_) => ChatScreen(remoteUserId: peer)),
      );
    } catch (e) {
      if (mounted) {
        setState(() => _error = _friendly(e));
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  String _friendly(Object e) {
    final text = e.toString();
    if (text.contains('No user') || text.contains('404')) {
      return 'That user is not registered on this relay. They need to '
          'enroll first, against the same relay address.';
    }
    if (text.contains('SocketException') || text.contains('TimeoutException')) {
      return 'Could not reach the relay. Check Settings.';
    }
    return text;
  }
}

/// A prominent, tappable option row used for the two in-person contact
/// exchange paths.
class _PrimaryOption extends StatelessWidget {
  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback onTap;

  const _PrimaryOption({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(14),
      child: Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: AppColors.surfaceHigh,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: AppColors.secure.withValues(alpha: 0.35)),
        ),
        child: Row(
          children: [
            Icon(icon, color: AppColors.secure, size: 24),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: const TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 15,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 3),
                  Text(
                    subtitle,
                    style: const TextStyle(
                      color: AppColors.textMuted,
                      fontSize: 12,
                      height: 1.4,
                    ),
                  ),
                ],
              ),
            ),
            const Icon(Icons.chevron_right, color: AppColors.textMuted, size: 20),
          ],
        ),
      ),
    );
  }
}
