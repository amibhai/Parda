import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../crypto/plaintext_handle.dart';
import '../models/message.dart';
import '../services/session_service.dart';
import '../theme/app_theme.dart';
import 'safety_number_screen.dart';

/// End-to-end encrypted 1:1 chat.
class ChatScreen extends StatefulWidget {
  final String remoteUserId;

  const ChatScreen({super.key, required this.remoteUserId});

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final _inputController = TextEditingController();
  final _scrollController = ScrollController();
  bool _sending = false;
  int _lastMessageCount = 0;

  @override
  void dispose() {
    _inputController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 220),
          curve: Curves.easeOut,
        );
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final session = context.watch<SessionService>();
    final msgs = session.messagesFor(widget.remoteUserId);
    final localUserId = session.localUserId ?? '';

    // Only auto-scroll when the conversation actually grew. Scrolling on
    // every rebuild fought the user whenever they scrolled up to read
    // back through history.
    if (msgs.length != _lastMessageCount) {
      _lastMessageCount = msgs.length;
      _scrollToBottom();
    }

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(
              widget.remoteUserId,
              style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 16,
                fontWeight: FontWeight.w600,
              ),
            ),
            const SizedBox(height: 2),
            Row(
              children: [
                const Icon(Icons.lock, size: 11, color: AppColors.secure),
                const SizedBox(width: 4),
                Text(
                  'End-to-end encrypted',
                  style: TextStyle(
                    color: AppColors.secure.withValues(alpha: 0.9),
                    fontSize: 11,
                  ),
                ),
              ],
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.verified_user_outlined, size: 21),
            tooltip: 'Verify safety number',
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute(
                builder: (_) => SafetyNumberScreen(remoteUserId: widget.remoteUserId),
              ),
            ),
          ),
          PopupMenuButton<String>(
            color: AppColors.surfaceHigh,
            icon: const Icon(Icons.more_vert, size: 21),
            onSelected: (v) {
              if (v == 'burn') _confirmBurn(session);
            },
            itemBuilder: (_) => const [
              PopupMenuItem(
                value: 'burn',
                child: Row(
                  children: [
                    Icon(Icons.local_fire_department_outlined,
                        size: 18, color: AppColors.danger),
                    SizedBox(width: 10),
                    Text('Burn conversation',
                        style: TextStyle(color: AppColors.danger, fontSize: 14)),
                  ],
                ),
              ),
            ],
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(color: AppColors.border, height: 1),
        ),
      ),
      body: Column(
        children: [
          Expanded(
            child: msgs.isEmpty
                ? const _EmptyConversation()
                : ListView.builder(
                    controller: _scrollController,
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
                    itemCount: msgs.length,
                    itemBuilder: (ctx, i) => _ChatBubble(
                      key: ValueKey(msgs[i].id),
                      message: msgs[i],
                      isMe: msgs[i].senderId == localUserId,
                    ),
                  ),
          ),
          _buildInputBar(session),
        ],
      ),
    );
  }

  Widget _buildInputBar(SessionService session) {
    final offline = session.relayStatus == RelayStatus.offline;
    return Container(
      decoration: const BoxDecoration(
        color: AppColors.surface,
        border: Border(top: BorderSide(color: AppColors.border)),
      ),
      child: SafeArea(
        top: false,
        child: Column(
          children: [
            if (offline)
              Container(
                width: double.infinity,
                padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 16),
                color: AppColors.danger.withValues(alpha: 0.14),
                child: const Text(
                  'Relay unreachable — messages will fail to send',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: AppColors.danger, fontSize: 11.5),
                ),
              ),
            Padding(
              padding: const EdgeInsets.fromLTRB(12, 10, 12, 10),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.end,
                children: [
                  Expanded(
                    child: TextField(
                      controller: _inputController,
                      style: const TextStyle(color: AppColors.textPrimary, fontSize: 15),
                      maxLines: 5,
                      minLines: 1,
                      textCapitalization: TextCapitalization.sentences,
                      decoration: InputDecoration(
                        hintText: 'Encrypted message…',
                        contentPadding: const EdgeInsets.symmetric(
                            horizontal: 16, vertical: 12),
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(24),
                          borderSide: const BorderSide(color: AppColors.border),
                        ),
                        enabledBorder: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(24),
                          borderSide: const BorderSide(color: AppColors.border),
                        ),
                        focusedBorder: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(24),
                          borderSide: const BorderSide(color: AppColors.secure),
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),
                  _SendButton(sending: _sending, onTap: _sendMessage),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _sendMessage() async {
    final body = _inputController.text.trim();
    if (body.isEmpty || _sending) return;

    setState(() => _sending = true);
    _inputController.clear();

    try {
      await context.read<SessionService>().sendMessage(widget.remoteUserId, body);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Send failed: ${_friendly(e)}'),
            backgroundColor: AppColors.danger,
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  String _friendly(Object e) {
    final t = e.toString();
    if (t.contains('SocketException') || t.contains('TimeoutException')) {
      return 'relay unreachable';
    }
    if (t.contains('No user') || t.contains('404')) {
      return 'recipient not registered on this relay';
    }
    return t;
  }

  Future<void> _confirmBurn(SessionService session) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Burn conversation?'),
        content: const Text(
          'Removes the session and all messages with this contact from this '
          'device. You will need to start a new session to talk again.\n\n'
          'This removes PARDA\'s own records. It cannot guarantee byte-level '
          'erasure of key material inside libsignal.',
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
            child: const Text('Burn'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await session.burnConversation(widget.remoteUserId);
    if (mounted) Navigator.of(context).pop();
  }
}

class _EmptyConversation extends StatelessWidget {
  const _EmptyConversation();

  @override
  Widget build(BuildContext context) => Center(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 48),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(Icons.lock_outline, size: 42, color: AppColors.textMuted.withValues(alpha: 0.6)),
              const SizedBox(height: 16),
              const Text(
                'Messages are end-to-end encrypted',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 14,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 8),
              const Text(
                'Verify the safety number in person to be sure nobody '
                'substituted keys when this conversation started.',
                textAlign: TextAlign.center,
                style: TextStyle(color: AppColors.textMuted, fontSize: 12.5, height: 1.5),
              ),
            ],
          ),
        ),
      );
}

class _SendButton extends StatelessWidget {
  final bool sending;
  final VoidCallback onTap;
  const _SendButton({required this.sending, required this.onTap});

  @override
  Widget build(BuildContext context) => GestureDetector(
        onTap: sending ? null : onTap,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 180),
          width: 46,
          height: 46,
          decoration: BoxDecoration(
            gradient: sending ? null : AppColors.brandGradient,
            color: sending ? AppColors.surfaceHigh : null,
            shape: BoxShape.circle,
          ),
          child: sending
              ? const Padding(
                  padding: EdgeInsets.all(13),
                  child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white70),
                )
              : const Icon(Icons.arrow_upward_rounded, color: Colors.white, size: 22),
        ),
      );
}

// ─── Chat bubble ─────────────────────────────────────────────────────────────

/// Stateful so a received message's plaintext can be read once from its
/// native handle and cached in widget state — see `SessionService`'s
/// docs for why the handle itself outlives this widget, and
/// `models/message.dart` for why sent messages skip this path.
class _ChatBubble extends StatefulWidget {
  final Message message;
  final bool isMe;

  const _ChatBubble({super.key, required this.message, required this.isMe});

  @override
  State<_ChatBubble> createState() => _ChatBubbleState();
}

class _ChatBubbleState extends State<_ChatBubble> {
  String? _renderedBody;
  bool _unavailable = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    if (widget.message.body != null) {
      _renderedBody = widget.message.body;
      return;
    }
    final handleId = widget.message.plaintextHandleId;
    if (handleId == null) {
      _unavailable = true;
      return;
    }
    final body = await PlaintextHandle(handleId).renderCopy();
    if (!mounted) return;
    setState(() {
      _renderedBody = body;
      // A released handle returns null. Saying so beats an ellipsis that
      // never resolves.
      _unavailable = body == null;
    });
  }

  @override
  Widget build(BuildContext context) {
    final isMe = widget.isMe;
    final failed = widget.message.status == MessageStatus.failed;

    return Align(
      alignment: isMe ? Alignment.centerRight : Alignment.centerLeft,
      child: ConstrainedBox(
        constraints: BoxConstraints(
          maxWidth: MediaQuery.of(context).size.width * 0.78,
        ),
        child: Container(
          margin: const EdgeInsets.symmetric(vertical: 3),
          padding: const EdgeInsets.fromLTRB(14, 10, 14, 8),
          decoration: BoxDecoration(
            gradient: isMe && !failed
                ? const LinearGradient(
                    colors: [AppColors.accent, Color(0xFF004DCC)],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  )
                : null,
            color: failed
                ? AppColors.danger.withValues(alpha: 0.18)
                : (isMe ? null : AppColors.surfaceHigh),
            border: failed
                ? Border.all(color: AppColors.danger.withValues(alpha: 0.5))
                : null,
            borderRadius: BorderRadius.only(
              topLeft: const Radius.circular(18),
              topRight: const Radius.circular(18),
              bottomLeft: Radius.circular(isMe ? 18 : 5),
              bottomRight: Radius.circular(isMe ? 5 : 18),
            ),
          ),
          child: Column(
            crossAxisAlignment:
                isMe ? CrossAxisAlignment.end : CrossAxisAlignment.start,
            children: [
              Text(
                _unavailable ? 'Message no longer available' : (_renderedBody ?? '…'),
                style: TextStyle(
                  color: _unavailable ? AppColors.textMuted : Colors.white,
                  fontSize: 15,
                  height: 1.35,
                  fontStyle: _unavailable ? FontStyle.italic : FontStyle.normal,
                ),
              ),
              const SizedBox(height: 4),
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    DateFormat('HH:mm').format(widget.message.timestamp),
                    style: TextStyle(
                      color: Colors.white.withValues(alpha: 0.55),
                      fontSize: 10.5,
                    ),
                  ),
                  if (isMe) ...[
                    const SizedBox(width: 5),
                    _statusIcon(widget.message.status),
                  ],
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _statusIcon(MessageStatus status) {
    switch (status) {
      case MessageStatus.sending:
        return const SizedBox(
          width: 11,
          height: 11,
          child: CircularProgressIndicator(strokeWidth: 1.4, color: Colors.white54),
        );
      case MessageStatus.sent:
        return const Icon(Icons.check, size: 12, color: Colors.white54);
      case MessageStatus.delivered:
        return const Icon(Icons.done_all, size: 12, color: AppColors.secure);
      case MessageStatus.failed:
        return const Icon(Icons.error_outline, size: 12, color: AppColors.danger);
      case MessageStatus.received:
        return const SizedBox.shrink();
    }
  }
}
