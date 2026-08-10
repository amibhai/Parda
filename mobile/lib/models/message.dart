/// A locally-held message — composed here (sent) or decrypted from the
/// relay (received).
///
/// ## Where the text lives, and why there are two places
///
/// - [body] is set once the text is available as a Dart `String`: for
///   sent messages always (it was typed here and never crossed a
///   decrypt boundary), and for received messages once
///   [plaintextHandleId] has been read through
///   `PlaintextHandle.renderCopy()` or the message was loaded back from
///   encrypted history.
/// - [plaintextHandleId] is the native, zeroize-on-release buffer a
///   freshly-decrypted message arrives in (`PlaintextBridge.kt` /
///   `protocol::plaintext_ffi`). It exists so decrypted bytes are not
///   handed straight to Dart — see
///   `docs/phase4.5c-dart-plaintext-design.md`.
///
/// Originally exactly one of the two was set, and received messages
/// carried *only* a handle. That made the app unusable: handles are
/// released when the app is backgrounded, so any received message
/// scrolled off-screen and back came up as permanently unavailable, and
/// nothing survived a restart. A message now caches its rendered text
/// once read, and encrypted history (`MessageStore.kt`) is what makes it
/// durable. The cost of that decision is stated on `MessageStore`
/// itself, not buried here.
class Message {
  final String id;
  final String conversationId; // typically the remote user ID
  final String senderId;
  final String? body;
  final int? plaintextHandleId;
  final DateTime timestamp;
  final MessageStatus status;

  const Message({
    required this.id,
    required this.conversationId,
    required this.senderId,
    this.body,
    this.plaintextHandleId,
    required this.timestamp,
    required this.status,
  }) : assert(
          body != null || plaintextHandleId != null,
          'a message must have either rendered text or a handle to read it from',
        );

  bool get isOutgoing => status == MessageStatus.sent ||
      status == MessageStatus.delivered ||
      status == MessageStatus.sending;

  Message copyWith({MessageStatus? status, String? body}) => Message(
        id: id,
        conversationId: conversationId,
        senderId: senderId,
        body: body ?? this.body,
        plaintextHandleId: plaintextHandleId,
        timestamp: timestamp,
        status: status ?? this.status,
      );

  /// Rebuild a message read back from encrypted history. Such a message
  /// has no live handle — its text is the stored copy.
  factory Message.fromHistory(Map<String, dynamic> row, String localUserId) {
    final outgoing = row['outgoing'] == true;
    return Message(
      id: row['id'] as String,
      conversationId: row['peer'] as String,
      senderId: row['senderId'] as String,
      body: row['body'] as String? ?? '',
      timestamp: DateTime.fromMillisecondsSinceEpoch((row['ts'] as num?)?.toInt() ?? 0),
      status: outgoing ? MessageStatus.sent : MessageStatus.received,
    );
  }
}

enum MessageStatus {
  /// Being encrypted and uploaded.
  sending,
  /// Accepted by relay server.
  sent,
  /// Fetched by the recipient (Phase 2: delivery receipts).
  delivered,
  /// Decryption failed.
  failed,
  /// Received and decrypted by the local user.
  received,
}

/// A summary of a conversation shown on the contacts/home screen.
class Conversation {
  final String remoteUserId;
  final String? displayName;
  final Message? lastMessage;
  final int unreadCount;

  const Conversation({
    required this.remoteUserId,
    this.displayName,
    this.lastMessage,
    this.unreadCount = 0,
  });

  String get title => displayName ?? remoteUserId;
}
