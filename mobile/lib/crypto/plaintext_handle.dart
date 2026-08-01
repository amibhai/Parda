import 'dart:convert';
import 'package:flutter/services.dart';

/// Dart-side handle to a native, zeroize-on-release plaintext buffer
/// (Sub-Phase 4.5C — see `docs/phase4.5c-dart-plaintext-design.md`).
///
/// Wraps an opaque native handle ID (a `Long` on the Android side,
/// `PlaintextBridge`'s boxed `PlaintextHandle` pointer — not the raw
/// pointer itself, platform channels don't marshal pointers safely).
/// The decrypted content this wraps was **never sent across this or any
/// platform channel** — only this ID was, and only this ID is sent back
/// for each of the calls below.
///
/// ## What this proves, and what it doesn't
///
/// The native buffer this wraps is zeroized and unlocked once [release]
/// is called — provably, on Linux/Android (see
/// `protocol/src/plaintext_ffi.rs`'s `/proc/self/mem` canary test).
/// **[renderCopy] itself still hands back a Dart `String`** — Flutter's
/// `Text` widget takes nothing else, and Dart has no mutable string
/// storage to scrub. Each call re-reads from the native buffer rather
/// than a cached copy, and the transient [Uint8List] used to decode it
/// is zero-filled immediately after decoding — but the resulting
/// `String` is exactly as long-lived as whatever holds a reference to
/// it, same as any other Dart string in this app. See the design note
/// §4 for why this is a narrowing, not an elimination, of the exposure
/// window.
class PlaintextHandle {
  static const MethodChannel _channel = MethodChannel('com.parda.app/plaintext');

  final int id;
  bool _released = false;

  PlaintextHandle(this.id);

  /// Copies the current plaintext out of the native buffer and decodes
  /// it as UTF-8. Returns `null` if the handle is `0`, already
  /// released, or the native call fails — callers must treat that as
  /// "this message's plaintext is no longer available," not retry with
  /// stale data.
  Future<String?> renderCopy() async {
    if (id == 0 || _released) return null;
    final bytes = await _channel.invokeMethod<Uint8List>('copyInto', {'handle': id});
    if (bytes == null) return null;
    try {
      return utf8.decode(bytes);
    } finally {
      // Zero this transient Dart-side buffer immediately after decode —
      // it cannot reach into the `String` just returned (Dart strings
      // are immutable; see class docs), but it does remove the one
      // Dart-owned mutable copy that exists between the platform-channel
      // handoff and the decode.
      bytes.fillRange(0, bytes.length, 0);
    }
  }

  /// Zeroizes and frees the native buffer. Idempotent — safe to call
  /// more than once, and safe to call on a handle whose ID is `0`
  /// (nothing was ever allocated).
  Future<void> release() async {
    if (_released || id == 0) return;
    _released = true;
    await _channel.invokeMethod<void>('release', {'handle': id});
  }
}
