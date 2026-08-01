/// Represents a locally-held message — either composed locally (sent)
/// or decrypted from the relay (received).
///
/// Exactly one of [body] / [plaintextHandleId] is set, never both:
///
/// - **Sent** messages carry [body] directly. This text originated as a
///   Dart `String` typed into the compose field — it never crossed a
///   native-decrypt boundary, so the Sub-Phase 4.5C concern below
///   doesn't apply to it the same way (see
///   `docs/phase4.5c-dart-plaintext-design.md` §2).
/// - **Received** messages carry [plaintextHandleId] instead: an opaque
///   handle into a native, zeroize-on-release buffer
///   (`PlaintextBridge.kt` / `protocol::plaintext_ffi`). Rendering code
///   must go through `PlaintextHandle(plaintextHandleId).renderCopy()`
///   (see `crypto/plaintext_handle.dart`), not read a cached `String` —
///   this class deliberately never holds one for received content.
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
          (body == null) != (plaintextHandleId == null),
          'exactly one of body / plaintextHandleId must be set',
        );

  bool get isOutgoing => status == MessageStatus.sent ||
      status == MessageStatus.delivered ||
      status == MessageStatus.sending;

  Message copyWith({MessageStatus? status}) => Message(
        id: id,
        conversationId: conversationId,
        senderId: senderId,
        body: body,
        plaintextHandleId: plaintextHandleId,
        timestamp: timestamp,
        status: status ?? this.status,
      );
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
