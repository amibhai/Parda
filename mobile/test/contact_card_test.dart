// Contact-card parsing is the gate on physical key exchange: anything
// it accepts becomes a session, and anything it wrongly rejects makes
// the feature look broken. These tests pin both directions.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:parda_mobile/models/contact_card.dart';

Map<String, dynamic> validCardMap() => {
      'v': 1,
      'user_id': 'alice',
      'registration_id': 1234,
      'device_id': 1,
      'identity_key': 'BcBSW4zuZfpaoAekU3rI4fuOcxvFAT+mWxI2V93zjctM',
      'signed_prekey_id': 1,
      'signed_prekey_public': 'BeW2lhZ0YliVOI1jRuqP0IzL1qC/GJMiZaWoJkQlW/FK',
      'signed_prekey_signature': 'pZJhlI5GDULB7vi9i83JBBxoqZ2Cp16WbQ==',
      'one_time_prekey_id': 7,
      'one_time_prekey_public': 'BXH3jZ5YWpnFTzC+6jdlJs5Cw2e7Z5CsH1G0e/pXr1UT',
    };

void main() {
  group('ContactCard.tryParse', () {
    test('accepts a well-formed card', () {
      final card = ContactCard.tryParse(jsonEncode(validCardMap()));
      expect(card, isNotNull);
      expect(card!.userId, 'alice');
      expect(card.identityKey, validCardMap()['identity_key']);
    });

    test('returns null for QR codes that are not contact cards', () {
      // A camera pointed at the world finds plenty of these; the scanner
      // has to ignore them quietly rather than throwing.
      expect(ContactCard.tryParse('https://example.com'), isNull);
      expect(ContactCard.tryParse('WIFI:S:somenetwork;T:WPA;P:hunter2;;'), isNull);
      expect(ContactCard.tryParse(''), isNull);
      expect(ContactCard.tryParse('{not json'), isNull);
    });

    test('rejects a JSON object that is not a card', () {
      expect(ContactCard.tryParse('{"hello":"world"}'), isNull);
      expect(ContactCard.tryParse('[1,2,3]'), isNull);
    });

    test('rejects an unknown format version', () {
      // Fail closed on a version this build does not understand rather
      // than parsing part of it — the same discipline the wire envelope
      // applies.
      final future = validCardMap()..['v'] = 99;
      expect(ContactCard.tryParse(jsonEncode(future)), isNull);
    });

    test('rejects a card missing any field needed to build a session', () {
      for (final field in const [
        'user_id',
        'registration_id',
        'identity_key',
        'signed_prekey_id',
        'signed_prekey_public',
        'signed_prekey_signature',
      ]) {
        final broken = validCardMap()..remove(field);
        expect(
          ContactCard.tryParse(jsonEncode(broken)),
          isNull,
          reason: 'a card without $field cannot produce a session',
        );
      }
    });

    test('accepts a card with no one-time prekey', () {
      // A peer whose pool is momentarily empty is still contactable;
      // X3DH proceeds without the one-time prekey.
      final card = validCardMap()
        ..remove('one_time_prekey_id')
        ..remove('one_time_prekey_public');
      expect(ContactCard.tryParse(jsonEncode(card)), isNotNull);
    });
  });

  group('round trip', () {
    test('encode then parse preserves the card', () {
      final original = ContactCard(validCardMap());
      final parsed = ContactCard.tryParse(original.encode());
      expect(parsed, isNotNull);
      expect(parsed!.userId, original.userId);
      expect(parsed.identityKey, original.identityKey);
    });

    test('withRelay attaches a relay hint without disturbing the keys', () {
      final card = ContactCard(validCardMap()).withRelay('http://10.0.0.5:8080');
      expect(card.relayUrl, 'http://10.0.0.5:8080');
      expect(card.identityKey, validCardMap()['identity_key']);
      expect(ContactCard.tryParse(card.encode())!.relayUrl, 'http://10.0.0.5:8080');
    });

    test('a card with no relay hint parses with a null relay', () {
      expect(ContactCard(validCardMap()).relayUrl, isNull);
    });
  });

  test('the QR payload stays small enough to scan comfortably', () {
    // Contact cards are shown as QR codes read at arm's length. Past
    // roughly a kilobyte the module count climbs and phone cameras
    // struggle, so this guards against a field being added carelessly.
    final payload = ContactCard(validCardMap())
        .withRelay('https://relay.example.com:8443')
        .encode();
    expect(payload.length, lessThan(1000),
        reason: 'payload was ${payload.length} bytes');
  });

  test('short fingerprint is stable and readable', () {
    final card = ContactCard(validCardMap());
    expect(card.shortIdentityFingerprint, ContactCard(validCardMap()).shortIdentityFingerprint);
    expect(card.shortIdentityFingerprint.split(' ').length, 3);
  });
}
