import 'dart:convert';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import '../config/app_config.dart';

/// HTTP client for the PARDA relay server.
///
/// All data sent to and received from the relay is opaque ciphertext
/// from the server's perspective. This service only handles serialisation
/// and HTTP transport — it has no access to key material or plaintext.
class ApiService {
  final String _baseUrl;
  final http.Client _client;

  ApiService({String? baseUrl, http.Client? client})
      : _baseUrl = baseUrl ?? AppConfig.relayBaseUrl,
        _client = client ?? http.Client();

  // ── Prekey bundle management ─────────────────────────────────────────────

  /// Upload a prekey bundle to the relay after identity generation.
  Future<void> uploadPreKeyBundle(
    String userId,
    Map<String, dynamic> bundle,
  ) async {
    final uri = Uri.parse('$_baseUrl/v1/keys/$userId');
    final response = await _client.post(
      uri,
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(bundle),
    );
    _assertOk(response, 'upload prekey bundle');
  }

  /// Fetch another user's prekey bundle to initiate a session.
  Future<Map<String, dynamic>> fetchPreKeyBundle(String remoteUserId) async {
    final uri = Uri.parse('$_baseUrl/v1/keys/$remoteUserId');
    final response = await _client.get(uri);
    _assertOk(response, 'fetch prekey bundle');
    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  // ── Messaging ────────────────────────────────────────────────────────────

  /// Submit an encrypted envelope to the relay for delivery.
  Future<String> submitMessage(
    String recipientId,
    Map<String, dynamic> envelopeJson,
  ) async {
    final uri = Uri.parse('$_baseUrl/v1/messages/$recipientId');
    final response = await _client.post(
      uri,
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(envelopeJson),
    );
    _assertOk(response, 'submit message', expectedStatus: 201);
    final body = jsonDecode(response.body) as Map<String, dynamic>;
    return body['message_id'] as String;
  }

  /// Fetch and drain all pending messages for [userId] from the relay.
  ///
  /// The relay deletes envelopes on drain. The client must persist
  /// decrypted plaintext locally before returning.
  Future<List<Map<String, dynamic>>> fetchMessages(String userId) async {
    final uri = Uri.parse('$_baseUrl/v1/messages/$userId');
    final response = await _client.get(uri);
    _assertOk(response, 'fetch messages');
    final body = jsonDecode(response.body) as Map<String, dynamic>;
    final messages = body['messages'] as List<dynamic>;
    return messages.cast<Map<String, dynamic>>();
  }

  /// Acknowledge and delete a single message from the relay queue.
  Future<void> deleteMessage(String userId, String messageId) async {
    final uri = Uri.parse('$_baseUrl/v1/messages/$userId/$messageId');
    final response = await _client.delete(uri);
    _assertOk(response, 'delete message');
  }

  // ── Health ───────────────────────────────────────────────────────────────

  /// Verify relay is reachable.
  Future<bool> healthCheck() async {
    try {
      final uri = Uri.parse('$_baseUrl/health');
      final response = await _client.get(uri).timeout(const Duration(seconds: 3));
      return response.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  void _assertOk(http.Response response, String operation, {int expectedStatus = 200}) {
    if (response.statusCode != expectedStatus) {
      throw ApiException(
        operation: operation,
        statusCode: response.statusCode,
        body: response.body,
      );
    }
  }
}

class ApiException implements Exception {
  final String operation;
  final int statusCode;
  final String body;

  ApiException({
    required this.operation,
    required this.statusCode,
    required this.body,
  });

  @override
  String toString() =>
      'ApiException[$operation]: HTTP $statusCode — $body';
}
