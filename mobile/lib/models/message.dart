import 'dart:convert';

/// Represents a decrypted, locally-stored message.
class Message {
  final String id;
  final String conversationId; // typically the remote user ID
  final String senderId;
  final String body;
  final DateTime timestamp;
  final MessageStatus status;

  const Message({
    required this.id,
    required this.conversationId,
    required this.senderId,
    required this.body,
    required this.timestamp,
    required this.status,
  });

  bool get isOutgoing => status == MessageStatus.sent ||
      status == MessageStatus.delivered ||
      status == MessageStatus.sending;

  Message copyWith({MessageStatus? status}) => Message(
        id: id,
        conversationId: conversationId,
        senderId: senderId,
        body: body,
        timestamp: timestamp,
        status: status ?? this.status,
      );

  Map<String, dynamic> toJson() => {
        'id': id,
        'conversationId': conversationId,
        'senderId': senderId,
        'body': body,
        'timestamp': timestamp.millisecondsSinceEpoch,
        'status': status.name,
      };

  factory Message.fromJson(Map<String, dynamic> json) => Message(
        id: json['id'] as String,
        conversationId: json['conversationId'] as String,
        senderId: json['senderId'] as String,
        body: json['body'] as String,
        timestamp: DateTime.fromMillisecondsSinceEpoch(json['timestamp'] as int),
        status: MessageStatus.values.byName(json['status'] as String),
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
