import 'dart:convert';

/// Everything a peer needs to open a session with this device, exchanged
/// **in person** rather than through the relay.
///
/// ## Why this is the security-relevant path, not just a convenience
///
/// Fetching a bundle from `/v1/keys/{id}` is trust-on-first-use: the
/// relay returns whatever key it holds, and a malicious or compromised
/// one can substitute its own. That is the first-contact MITM
/// `docs/phase4.5d-trust-bootstrapping-design.md` §4 records as
/// undefended — and comparing safety numbers afterwards only helps if
/// somebody actually compares them.
///
/// A card scanned off another person's screen never passes through the
/// relay at all, so the relay is out of the key-exchange path. Importing
/// one therefore marks the peer *verified*, and any later key change for
/// them becomes a hard failure instead of a silent re-pin.
///
/// ## Wire format
///
/// Compact JSON, because it has to fit in a QR code a phone camera can
/// resolve at arm's length. Field names are the relay's
/// `PreKeyBundleJson` names plus `user_id`, `v`, and an optional
/// `relay` hint, so the same map is accepted by both the QR importer and
/// the existing bundle-processing path with no translation layer.
class ContactCard {
  /// Format version. Rejecting an unknown version outright is the same
  /// fail-closed discipline `MessageEnvelope::validate_version` applies
  /// on the wire — better a clear "update the app" than a partial parse.
  static const int currentVersion = 1;

  final Map<String, dynamic> raw;

  const ContactCard(this.raw);

  String get userId => raw['user_id'] as String;
  String get identityKey => raw['identity_key'] as String;
  String? get relayUrl => raw['relay'] as String?;

  /// Attach the relay this device is using, so a scanner can point at
  /// the same one without being told it separately. Advisory: the
  /// scanning device decides whether to adopt it.
  ContactCard withRelay(String relayUrl) =>
      ContactCard({...raw, 'relay': relayUrl});

  String encode() => jsonEncode(raw);

  /// Parse a scanned payload.
  ///
  /// Returns `null` for anything that is not a PARDA card — a camera
  /// pointed at the world finds plenty of other QR codes, and the
  /// scanner UI needs to ignore them quietly rather than throwing.
  static ContactCard? tryParse(String payload) {
    try {
      final decoded = jsonDecode(payload);
      if (decoded is! Map<String, dynamic>) return null;
      if (decoded['v'] != currentVersion) return null;
      // The minimum needed to build a PreKeyBundle. A card missing any
      // of these would fail deeper in native code with a far less
      // helpful message.
      for (final field in const [
        'user_id',
        'registration_id',
        'identity_key',
        'signed_prekey_id',
        'signed_prekey_public',
        'signed_prekey_signature',
      ]) {
        if (decoded[field] == null) return null;
      }
      return ContactCard(decoded);
    } catch (_) {
      return null;
    }
  }

  /// A short, human-checkable rendering of the identity key.
  ///
  /// Not a safety number — that is a function of *both* parties' keys
  /// and lives in `safety_number_screen.dart`. This exists so two people
  /// holding phones can sanity-check that a scan landed on the right
  /// card before trusting it.
  String get shortIdentityFingerprint {
    final key = identityKey.replaceAll(RegExp(r'[^A-Za-z0-9]'), '');
    if (key.length < 12) return key;
    return '${key.substring(0, 4)} ${key.substring(4, 8)} ${key.substring(8, 12)}';
  }
}
