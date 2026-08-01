import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../models/message.dart';
import '../services/session_service.dart';
import 'chat_screen.dart';

/// Home screen — lists active conversations.
class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  @override
  Widget build(BuildContext context) {
    final session = context.watch<SessionService>();
    final conversations = session.messages.keys.toList();

    return Scaffold(
      backgroundColor: const Color(0xFF0D1117),
      appBar: AppBar(
        backgroundColor: const Color(0xFF161B22),
        title: Row(
          children: [
            Container(
              width: 32,
              height: 32,
              decoration: BoxDecoration(
                gradient: const LinearGradient(
                  colors: [Color(0xFF00D084), Color(0xFF0066FF)],
                ),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Icon(Icons.shield, color: Colors.white, size: 18),
            ),
            const SizedBox(width: 12),
            const Text(
              'PARDA',
              style: TextStyle(
                color: Colors.white,
                fontWeight: FontWeight.w700,
                fontSize: 20,
                letterSpacing: 2,
              ),
            ),
          ],
        ),
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 8),
            child: Text(
              'v0.1.0-alpha',
              style: TextStyle(color: Colors.grey.shade600, fontSize: 11),
            ),
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(color: const Color(0xFF30363D), height: 1),
        ),
      ),
      body: conversations.isEmpty
          ? _buildEmptyState(context)
          : ListView.builder(
              itemCount: conversations.length,
              itemBuilder: (context, i) {
                final convoId = conversations[i];
                final msgs = session.messagesFor(convoId);
                final lastMsg = msgs.isNotEmpty ? msgs.last : null;
                return _ConversationTile(
                  conversationId: convoId,
                  lastMessage: lastMsg,
                  onTap: () => Navigator.of(context).push(
                    MaterialPageRoute(
                      builder: (_) => ChatScreen(remoteUserId: convoId),
                    ),
                  ),
                );
              },
            ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () => _showNewConversationDialog(context),
        backgroundColor: const Color(0xFF00D084),
        foregroundColor: Colors.black,
        icon: const Icon(Icons.lock_outline),
        label: const Text('New Secure Chat', style: TextStyle(fontWeight: FontWeight.w600)),
      ),
    );
  }

  Widget _buildEmptyState(BuildContext context) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            width: 80,
            height: 80,
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [Color(0xFF00D084), Color(0xFF0066FF)],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(20),
              boxShadow: [
                BoxShadow(
                  color: const Color(0xFF00D084).withOpacity(0.3),
                  blurRadius: 24,
                  spreadRadius: 4,
                ),
              ],
            ),
            child: const Icon(Icons.shield_outlined, color: Colors.white, size: 40),
          ),
          const SizedBox(height: 24),
          const Text(
            'No Conversations Yet',
            style: TextStyle(
              color: Colors.white,
              fontSize: 20,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'Start a new encrypted chat\nby tapping the button below.',
            textAlign: TextAlign.center,
            style: TextStyle(color: Colors.grey.shade500, fontSize: 14),
          ),
          const SizedBox(height: 8),
          Container(
            margin: const EdgeInsets.all(16),
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: const Color(0xFF161B22),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: const Color(0xFF30363D)),
            ),
            child: Text(
              '⚠️  Research prototype — not for operational use',
              style: TextStyle(color: Colors.amber.shade700, fontSize: 12),
              textAlign: TextAlign.center,
            ),
          ),
        ],
      ),
    );
  }

  void _showNewConversationDialog(BuildContext context) {
    final controller = TextEditingController();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF161B22),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        title: const Text('New Conversation', style: TextStyle(color: Colors.white)),
        content: TextField(
          controller: controller,
          autofocus: true,
          style: const TextStyle(color: Colors.white),
          decoration: InputDecoration(
            hintText: 'Enter recipient user ID',
            hintStyle: TextStyle(color: Colors.grey.shade600),
            filled: true,
            fillColor: const Color(0xFF0D1117),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: const BorderSide(color: Color(0xFF30363D)),
            ),
            enabledBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: const BorderSide(color: Color(0xFF30363D)),
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text('Cancel', style: TextStyle(color: Colors.grey.shade500)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF00D084),
              foregroundColor: Colors.black,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
            ),
            onPressed: () {
              final id = controller.text.trim();
              if (id.isNotEmpty) {
                Navigator.pop(ctx);
                Navigator.of(context).push(
                  MaterialPageRoute(
                    builder: (_) => ChatScreen(remoteUserId: id),
                  ),
                );
              }
            },
            child: const Text('Open Chat', style: TextStyle(fontWeight: FontWeight.w600)),
          ),
        ],
      ),
    );
  }
}

class _ConversationTile extends StatelessWidget {
  final String conversationId;
  final Message? lastMessage;
  final VoidCallback onTap;

  const _ConversationTile({
    required this.conversationId,
    required this.lastMessage,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        decoration: const BoxDecoration(
          border: Border(bottom: BorderSide(color: Color(0xFF21262D))),
        ),
        child: Row(
          children: [
            CircleAvatar(
              backgroundColor: const Color(0xFF0066FF).withOpacity(0.2),
              child: Text(
                conversationId.isNotEmpty ? conversationId[0].toUpperCase() : '?',
                style: const TextStyle(color: Color(0xFF0066FF), fontWeight: FontWeight.bold),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    conversationId,
                    style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600),
                  ),
                  if (lastMessage != null)
                    Text(
                      // Sub-Phase 4.5C: a received message's plaintext
                      // lives behind a native handle now, not a cached
                      // `String` (see models/message.dart) — deliberately
                      // not decoded just to populate this preview line,
                      // since every additional place that calls
                      // `renderCopy()` is one more place a Dart `String`
                      // materializes and lingers. Sent messages (typed
                      // locally, never crossed a decrypt boundary) still
                      // show their real text.
                      lastMessage!.body ?? '🔒 New message',
                      style: TextStyle(color: Colors.grey.shade500, fontSize: 13),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                ],
              ),
            ),
            const Icon(Icons.lock, color: Color(0xFF00D084), size: 14),
          ],
        ),
      ),
    );
  }
}
