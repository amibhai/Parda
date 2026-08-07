import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Dart-side handle to a native, zeroize-on-release plaintext buffer
/// (Sub-Phase 4.5C — see `docs/phase4.5c-dart-plaintext-design.md`).
///
/// Wraps an opaque native handle ID. The decrypted content this refers
/// to is **never sent across a platform channel except on an explicit
/// [renderCopy] call**; `decryptMessage` returns only this ID.
///
/// ## What this proves, and what it doesn't
///
/// The native buffer is zeroized and unlocked once [release] is called —
/// provably, on Android's Linux kernel (see
/// `protocol/src/plaintext_ffi.rs`'s `/proc/self/mem` canary test).
/// [renderCopy] still hands back a Dart `String`, because Flutter's
/// `Text` widget takes nothing else and Dart strings are immutable. Each
/// call re-reads from the native buffer rather than a cached copy, so
/// the window is one render pass rather than the whole session — a
/// narrowing, not an elimination. See the design note §4.
class PlaintextHandle {
  static const MethodChannel _channel = MethodChannel('com.parda.app/plaintext');

  final int id;
  bool _released = false;

  PlaintextHandle(this.id);

  /// Copy the plaintext out of the native buffer and decode it as UTF-8.
  ///
  /// Returns `null` if the handle is `0`, already released, or the
  /// native call fails — callers must treat that as "this message's
  /// plaintext is no longer available", not retry with stale data.
  Future<String?> renderCopy() async {
    if (id == 0 || _released) return null;
    try {
      final bytes =
          await _channel.invokeMethod<Uint8List>('copyInto', {'handle': id});
      if (bytes == null) return null;
      try {
        return utf8.decode(bytes);
      } finally {
        _bestEffortZero(bytes);
      }
    } on PlatformException catch (e) {
      debugPrint('[PlaintextHandle] copyInto failed: ${e.code} ${e.message}');
      return null;
    }
  }

  /// Overwrite the transient platform-channel buffer, if the platform
  /// lets us.
  ///
  /// **Finding, recorded rather than hidden (found on a real Pixel 8,
  /// Android 17, Flutter 3.44):** the `Uint8List` a `MethodChannel`
  /// hands back is an *unmodifiable view* over the channel's own
  /// receive buffer. Calling `fillRange` on it throws
  /// `UnsupportedError`. The first version of this method zeroed it
  /// unconditionally, so every single `renderCopy` threw before
  /// returning and no received message ever rendered — the throw was
  /// invisible because it surfaced only as a message stuck showing "…".
  ///
  /// The security consequence is real and is **not** solved here: on
  /// this platform the Dart-side copy of the plaintext cannot be
  /// scrubbed by application code, so it persists in the channel's
  /// buffer until Dart's GC reclaims it. Copying it into a modifiable
  /// list first would make matters worse, not better — that yields two
  /// copies and still leaves the original unscrubable. This is an
  /// addition to the design note's stated residual (the `String`), not
  /// a replacement for it: both the `String` *and* this byte buffer
  /// outlive the render pass by an amount the app does not control.
  void _bestEffortZero(Uint8List bytes) {
    try {
      bytes.fillRange(0, bytes.length, 0);
    } on UnsupportedError {
      // Expected on platform-channel buffers — see doc comment.
    }
  }

  /// Zeroize and free the native buffer. Idempotent.
  Future<void> release() async {
    if (_released || id == 0) return;
    _released = true;
    try {
      await _channel.invokeMethod<void>('release', {'handle': id});
    } on PlatformException catch (e) {
      debugPrint('[PlaintextHandle] release failed: ${e.code} ${e.message}');
    }
  }
}
