# Phase 4.5 / Sub-Phase 4.5C — Design Note: The Dart Plaintext Problem

**Status:** Design reviewed prior to implementation | **Date:** 2026-08-01

This note exists because the brief requires one before touching this
sub-phase's riskiest decision — the same standard `docs/phase3-3a-self-destruct-design.md`
and `docs/phase4-4c-dead-drop-addressing-design.md` were already held to.
The problem itself is not new: `docs/phase3-3a-self-destruct-design.md` §9
finding 3 already identified it precisely — `session_service.dart` converts
decrypted plaintext to a Dart `String` via `utf8.decode(plaintextBytes)`,
and Dart's `String` has no mutable backing storage, so no zeroize discipline
at any earlier layer (Rust, Kotlin) can make it provably erasable once that
conversion happens. This note designs the fix.

---

## 1. The finding this note has to state plainly before proposing anything

**Flutter's `Text` widget takes a Dart `String`.** There is no public
Flutter API — checked against Flutter's own `Text`/`RenderParagraph`/
`TextPainter` documentation, not assumed — to render text from a native
buffer or a `Uint8List` without materializing a `String` at the point of
rendering. The `String` that reaches `TextPainter` is retained for however
long the Flutter engine's own paragraph-layout cache and the widget tree's
`Element`/`RenderObject` retention choose to keep it — which is Dart
garbage-collector-timed, not something application code controls.

**Consequence, stated once here rather than implied away by the rest of
this note:** the fix below **narrows the exposure window from "the whole
app session" (today) to "one render pass," it does not eliminate the
gap.** This is the same class of honest boundary this project already
draws elsewhere — sealed sender "hides identity, not IP address"
(`docs/THREAT_MODEL.md` §3.5) is the closest precedent: a real, verified
improvement, stated with the specific thing it does not cover attached to
it, not detached into a footnote.

---

## 2. Design: a native-owned buffer, a per-render Dart copy

**Rust side** (new, small FFI surface — `protocol/src/plaintext_ffi.rs`,
reusing the zeroize/lock patterns already audited in `self_destruct.rs`/
`secure_memory.rs`, not a new primitive):

```rust
pub struct PlaintextHandle { /* Box<[u8]>, zeroize-on-drop, locked via
                                 secure_memory — identical discipline to
                                 self_destruct::DerivedKey, applied here
                                 to a plaintext buffer instead of a key */ }

// C ABI, called from Kotlin's JNI bridge:
extern "C" fn parda_plaintext_new(bytes: *const u8, len: usize) -> *mut PlaintextHandle;
extern "C" fn parda_plaintext_len(handle: *mut PlaintextHandle) -> usize;
extern "C" fn parda_plaintext_copy_into(handle: *mut PlaintextHandle, out: *mut u8, out_len: usize) -> bool;
extern "C" fn parda_plaintext_release(handle: *mut PlaintextHandle); // zeroize + free
```

**Dart side** (`mobile/lib/crypto/plaintext_handle.dart`, new): wraps a
handle ID (an opaque `int` returned across the platform channel, not the
raw pointer — Dart/Flutter platform channels don't marshal raw pointers
safely) with:

- `int lengthSync()` — asks the native side how many bytes are available,
  so the caller can size a `Uint8List` before copying.
- `Uint8List renderCopy()` — copies into a **freshly allocated, short-lived**
  `Uint8List`, decodes to a `String` only inside the exact `Text` build
  call site, and the `Uint8List` itself is zero-filled (`fillRange(0, len,
  0)`) immediately after that decode — the one native→Dart copy this
  design cannot avoid, scoped to the smallest span that could be achieved
  without forking Flutter's own text-rendering pipeline.
- `void release()` — calls `parda_plaintext_release`, explicitly, called
  from the message-list item's `dispose()`/scroll-off-screen path, not
  left to whenever Dart's GC happens to collect the wrapper object.

**`SessionService`'s history map stops holding decrypted `String` bodies at
all.** It holds `PlaintextHandle` references (or, for messages already
read and not self-destructing, nothing further to hold — matching
`client-store`'s existing "history stores ciphertext-adjacent state, not
long-lived plaintext" posture). Decryption happens once, immediately after
fetch, producing a handle; every subsequent render re-reads through
`renderCopy()` rather than a cached `String` sitting in memory for the rest
of the session.

## 3. Why not a stronger fix

**Forking Flutter's text rendering to accept a native buffer directly**
was considered and rejected: it would mean maintaining a patched Flutter
engine, a categorically larger maintenance and correctness-risk surface
than this project takes on anywhere else, for a narrowing (not
elimination) of an already-narrow window. Not proportionate to what Phase
3 itself already accepts as a residual for standard `String`-based text
(the window this design leaves is the same order of magnitude as a single
frame's paint, not a whole session).

## 4. What this does and doesn't prove

**Provable, and tested (§5):** the native `PlaintextHandle` is zeroized
(and, on Linux/Android's Linux-kernel-based process memory model, provably
absent from process memory after release — same technique
`self_destruct.rs`'s Linux tests already use) once `release()` is called,
and the SQLCipher-backed history store never persists a decrypted body at
all, matching `client-store`'s existing exclusion principle for
self-destructing messages, extended here to *all* rendered plaintext, not
just self-destructing plaintext.

**Not provable, stated directly:** the transient `Uint8List`/`String` pair
that exists for one render pass is real, live, unlocked process memory for
that pass's duration. A memory dump taken during exactly that window still
finds it — the same "an adversary with a memory dump before erasure fires
always gets the plaintext" statement `docs/THREAT_MODEL.md` §3.4 already
makes for the Rust-side primitive, extended here to the render path.

## 5. Test plan

`mesh`'s Android instrumented test (`mobile/android/app/src/androidTest/...`,
Sub-Phase 4.5C): push a distinctive canary plaintext through the full path
(Rust decrypt → `PlaintextHandle` → JNI → Dart `renderCopy()` → simulated
render → `release()`), then scan the running app process's own
`/proc/self/mem` (Android is Linux-kernel-based; a process can read its own
`/proc/self/mem` without special privilege) for the canary's exact bytes,
before release (must be found — sanity check on the scan technique itself)
and after (must be absent). This is the same technique
`protocol/src/self_destruct.rs`'s Linux-only tests and
`protocol/tests/forensic_recovery_tests.rs` already use, applied through
one more layer (JNI + Dart) than either has been asked to cross before.
