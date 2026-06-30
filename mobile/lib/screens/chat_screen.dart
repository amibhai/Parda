import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import '../models/message.dart';
import '../services/session_service.dart';

/// End-to-end encrypted 1:1 chat UI.
///
/// Messages are displayed as chat bubbles. All crypto is handled by
/// [SessionService] — this widget only shows decrypted plaintext
/// that is already in local state.
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
          duration: const Duration(milliseconds: 250),
          curve: Curves.easeOut,
        );
      }
    });
  }

  Future<void> _sendMessage() async {
    final body = _inputController.text.trim();
    if (body.isEmpty || _sending) return;

    setState(() => _sending = true);
    _inputController.clear();

    try {
      await context.read<SessionService>().sendMessage(widget.remoteUserId, body);
      _scrollToBottom();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Send failed: $e'),
            backgroundColor: const Color(0xFFDA3633),
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final session = context.watch<SessionService>();
    final msgs = session.messagesFor(widget.remoteUserId);
    final localUserId = session.localUserId ?? '';

    // Auto-scroll on new messages
    if (msgs.isNotEmpty) _scrollToBottom();

    return Scaffold(
      backgroundColor: const Color(0xFF0D1117),
      appBar: AppBar(
        backgroundColor: const Color(0xFF161B22),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios, color: Colors.white),
          onPressed: () => Navigator.of(context).pop(),
        ),
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              widget.remoteUserId,
              style: const TextStyle(
                  color: Colors.white, fontSize: 16, fontWeight: FontWeight.w600),
            ),
            Row(
              children: [
                Container(
                  width: 6,
                  height: 6,
                  decoration: const BoxDecoration(
                    color: Color(0xFF00D084),
                    shape: BoxShape.circle,
                  ),
                ),
                const SizedBox(width: 4),
                const Text(
                  'End-to-end encrypted',
                  style: TextStyle(color: Color(0xFF00D084), fontSize: 11),
                ),
              ],
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.lock, color: Color(0xFF00D084), size: 18),
            onPressed: () => _showSecurityInfo(context),
            tooltip: 'Security info',
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(color: const Color(0xFF30363D), height: 1),
        ),
      ),
      body: Column(
        children: [
          // Security notice banner
          Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 16),
            color: const Color(0xFF0D1117),
            child: Text(
              '🔐  Messages are encrypted with Signal Protocol (Phase 1)',
              textAlign: TextAlign.center,
              style: TextStyle(color: Colors.grey.shade600, fontSize: 11),
            ),
          ),

          // Message list
          Expanded(
            child: msgs.isEmpty
                ? Center(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(Icons.lock_clock, color: Colors.grey.shade700, size: 48),
                        const SizedBox(height: 12),
                        Text(
                          'No messages yet.\nSend the first encrypted message.',
                          textAlign: TextAlign.center,
                          style: TextStyle(color: Colors.grey.shade600, fontSize: 14),
                        ),
                      ],
                    ),
                  )
                : ListView.builder(
                    controller: _scrollController,
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                    itemCount: msgs.length,
                    itemBuilder: (ctx, i) {
                      final msg = msgs[i];
                      final isMe = msg.senderId == localUserId;
                      return _ChatBubble(message: msg, isMe: isMe);
                    },
                  ),
          ),

          // Input bar
          _buildInputBar(),
        ],
      ),
    );
  }

  Widget _buildInputBar() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: const BoxDecoration(
        color: Color(0xFF161B22),
        border: Border(top: BorderSide(color: Color(0xFF30363D))),
      ),
      child: SafeArea(
        child: Row(
          children: [
            Expanded(
              child: TextField(
                controller: _inputController,
                style: const TextStyle(color: Colors.white),
                maxLines: 4,
                minLines: 1,
                textInputAction: TextInputAction.send,
                onSubmitted: (_) => _sendMessage(),
                decoration: InputDecoration(
                  hintText: 'Encrypted message…',
                  hintStyle: TextStyle(color: Colors.grey.shade600),
                  filled: true,
                  fillColor: const Color(0xFF0D1117),
                  contentPadding:
                      const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(24),
                    borderSide: const BorderSide(color: Color(0xFF30363D)),
                  ),
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(24),
                    borderSide: const BorderSide(color: Color(0xFF30363D)),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(24),
                    borderSide: const BorderSide(color: Color(0xFF00D084)),
                  ),
                ),
              ),
            ),
            const SizedBox(width: 10),
            GestureDetector(
              onTap: _sending ? null : _sendMessage,
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 200),
                width: 44,
                height: 44,
                decoration: BoxDecoration(
                  gradient: _sending
                      ? null
                      : const LinearGradient(
                          colors: [Color(0xFF00D084), Color(0xFF0066FF)],
                          begin: Alignment.topLeft,
                          end: Alignment.bottomRight,
                        ),
                  color: _sending ? const Color(0xFF30363D) : null,
                  shape: BoxShape.circle,
                  boxShadow: _sending
                      ? null
                      : [
                          BoxShadow(
                            color: const Color(0xFF00D084).withOpacity(0.4),
                            blurRadius: 12,
                            spreadRadius: 2,
                          ),
                        ],
                ),
                child: _sending
                    ? const Padding(
                        padding: EdgeInsets.all(12),
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: Colors.white,
                        ),
                      )
                    : const Icon(Icons.send_rounded, color: Colors.white, size: 20),
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _showSecurityInfo(BuildContext context) {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF161B22),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (_) => Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              const Icon(Icons.lock, color: Color(0xFF00D084)),
              const SizedBox(width: 8),
              const Text(
                'Security Details',
                style: TextStyle(
                    color: Colors.white, fontSize: 18, fontWeight: FontWeight.w600),
              ),
            ]),
            const SizedBox(height: 16),
            _secInfoRow('Protocol', 'Signal Protocol (X3DH + Double Ratchet)'),
            _secInfoRow('Key Exchange', 'X25519 Elliptic Curve Diffie-Hellman'),
            _secInfoRow('Encryption', 'AES-256-CBC + HMAC-SHA256'),
            _secInfoRow('Forward Secrecy', 'Per-message ephemeral keys'),
            _secInfoRow('Key Storage', 'Android Keystore / iOS Secure Enclave'),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.amber.shade900.withOpacity(0.2),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: Colors.amber.shade800.withOpacity(0.4)),
              ),
              child: Text(
                '⚠ Research prototype. Not certified for operational use.\n'
                'No CNSA 2.0 or FIPS 140-3 compliance in Phase 1.',
                style: TextStyle(color: Colors.amber.shade600, fontSize: 12),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _secInfoRow(String label, String value) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 4),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(
              width: 120,
              child: Text(label, style: TextStyle(color: Colors.grey.shade500, fontSize: 13)),
            ),
            Expanded(
              child: Text(value, style: const TextStyle(color: Colors.white, fontSize: 13)),
            ),
          ],
        ),
      );
}

// ─── Chat bubble widget ───────────────────────────────────────────────────────

class _ChatBubble extends StatelessWidget {
  final Message message;
  final bool isMe;

  const _ChatBubble({required this.message, required this.isMe});

  @override
  Widget build(BuildContext context) {
    return Align(
      alignment: isMe ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: EdgeInsets.only(
          top: 4,
          bottom: 4,
          left: isMe ? 60 : 0,
          right: isMe ? 0 : 60,
        ),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        decoration: BoxDecoration(
          gradient: isMe
              ? const LinearGradient(
                  colors: [Color(0xFF0066FF), Color(0xFF004DCC)],
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                )
              : null,
          color: isMe ? null : const Color(0xFF21262D),
          borderRadius: BorderRadius.only(
            topLeft: const Radius.circular(18),
            topRight: const Radius.circular(18),
            bottomLeft: Radius.circular(isMe ? 18 : 4),
            bottomRight: Radius.circular(isMe ? 4 : 18),
          ),
          boxShadow: isMe
              ? [
                  BoxShadow(
                    color: const Color(0xFF0066FF).withOpacity(0.25),
                    blurRadius: 8,
                    offset: const Offset(0, 2),
                  ),
                ]
              : null,
        ),
        child: Column(
          crossAxisAlignment:
              isMe ? CrossAxisAlignment.end : CrossAxisAlignment.start,
          children: [
            Text(
              message.body,
              style: const TextStyle(color: Colors.white, fontSize: 15),
            ),
            const SizedBox(height: 4),
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  DateFormat('HH:mm').format(message.timestamp),
                  style: TextStyle(
                    color: Colors.white.withOpacity(0.5),
                    fontSize: 11,
                  ),
                ),
                if (isMe) ...[
                  const SizedBox(width: 4),
                  _statusIcon(message.status),
                ],
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _statusIcon(MessageStatus status) {
    switch (status) {
      case MessageStatus.sending:
        return const SizedBox(
          width: 12,
          height: 12,
          child: CircularProgressIndicator(strokeWidth: 1.5, color: Colors.white54),
        );
      case MessageStatus.sent:
        return const Icon(Icons.check, size: 13, color: Colors.white54);
      case MessageStatus.delivered:
        return const Icon(Icons.done_all, size: 13, color: Color(0xFF00D084));
      case MessageStatus.failed:
        return const Icon(Icons.error_outline, size: 13, color: Color(0xFFDA3633));
      case MessageStatus.received:
        return const SizedBox.shrink();
    }
  }
}
