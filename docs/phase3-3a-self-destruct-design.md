# Phase 3 / Sub-Phase 3A — Design Note: Time-Bound Key Derivation & Clock Trust

**Status:** Implemented and tested | **Date:** 2026-07-31 (design), 2026-07-31 (implementation + §5 addendum below)

This note exists because the Phase 3 brief explicitly requires it: the KDF
chain and clock-trust handling are "the phase's riskiest design decision"
and must be reviewed before code exists. Two things in this note are
**deviations or clarifications relative to the brief's literal wording**,
flagged prominently rather than silently implemented — see §1 and §3.

---

## 1. What key material actually anchors the KDF (and why it isn't the raw Double-Ratchet message key)

The brief specifies: *"a time-bound key derived via HKDF... from the
message's Double-Ratchet-derived key material."* Taken literally, this
means: take the actual per-message AES/HMAC key the Double Ratchet
derives, and feed it into HKDF as input keying material.

**This isn't accessible through the libsignal integration PARDA already
has, and reaching for it would violate a constraint the project already
committed to.** Concretely:

- `SessionManager::decrypt()` (`protocol/src/session.rs`) calls
  `libsignal_protocol::message_decrypt(...)`, whose Signal-message path
  (`message_decrypt_signal` in the pinned `v0.66.0` tag,
  `rust/protocol/src/session_cipher.rs`) returns `Result<Vec<u8>>` —
  plaintext only. The per-message ratchet key is derived and consumed
  entirely inside `decrypt_message_with_record`, never surfaced to the
  caller.
- Getting at it would mean either (a) forking/patching libsignal to
  expose internal ratchet state, or (b) reimplementing message
  decryption ourselves against the session record to intercept the key
  before libsignal uses it. Both are exactly the class of thing
  `docs/phase1-architecture.md` §2 already rejected as an alternative for
  the core protocol ("assembling audited primitives into an unaudited
  protocol breaks the no-custom-crypto constraint... even correct
  assembly of good primitives can introduce protocol-level
  vulnerabilities"). Doing it for Phase 3 would reopen that exact risk
  for no protocol-layer benefit.

**What Phase 3's self-destruct key is actually protecting is a different
thing than the Double-Ratchet key anyway.** The DR key's job is
confidentiality of the wire ciphertext, and Phase 1 already tests that it
gets discarded per-message (forward secrecy). By the time self-destruct
matters, that key is already gone — libsignal's own internals handled
it. What self-destruct needs to protect is **the recovered plaintext's
lifetime after decryption**, which is a strictly later, separate concern:
even with perfect forward secrecy on the wire, a decrypted message sitting
in the app's memory or local store indefinitely is exactly the gap Phase 3
exists to close.

**Design decision:** the self-destruct key is derived via HKDF
(RFC 5869, `hkdf` crate) from a **freshly-generated random secret**
(`OsRng`, 32 bytes — the same CSPRNG already used throughout
`protocol/src/identity.rs` and `session.rs`), generated locally at the
moment plaintext becomes available (post-`decrypt()` for a receiver).
This secret is never transmitted — self-destruct is a per-device
guarantee about that device's own copy, not shared protocol state
between sender and receiver, so there's no need for it to be derivable
by both sides. The envelope's `timestamp_ms` (and the destruct mode, and
a fixed context string) go into HKDF's `info` parameter for domain
separation and to bind the derived key to *this specific message's*
declared delivery time — not because `timestamp_ms` is itself trusted
(it's sender-supplied wire metadata; see §3 for what's actually trusted
for expiry timing).

```
IKM  = OsRng.gen::<[u8; 32]>()                          // fresh, local, never transmitted
salt = None (HKDF-Extract with an all-zero salt, per RFC 5869 §2.2)
info = b"PARDA-Phase3-SelfDestructKey-V1"
       || destruct_mode (1 byte: 0 = time-bound, 1 = read-triggered)
       || envelope.timestamp_ms (8 bytes, BE)
       || expiry_window_ms (8 bytes, BE, 0 for read-triggered)
PRK  = HKDF-Extract(salt, IKM)
OKM  = HKDF-Expand(PRK, info, 32)   // ChaCha20-Poly1305 key
```

**If this substitution isn't acceptable** — e.g. if the intent was
specifically to tie key destruction to the ratchet's own step function
rather than a separate local timer — that would require the fork/patch
approach above, which I'd want explicit sign-off on before attempting,
given the constraint it reopens.

---

## 2. Encryption of the plaintext under the derived key

The recovered plaintext is immediately re-encrypted under `OKM` using
ChaCha20-Poly1305 (`chacha20poly1305` crate, RustCrypto, AEAD, already
adjacent to this project's dependency tree via `sphinx-packet`'s
`chacha20` dependency, but added here as an explicit direct dependency —
no custom AEAD construction). The plaintext held only transiently during
this re-encryption step is itself wrapped in a `zeroize`-guarded buffer
(see §4) for the brief interval between `decrypt()` returning it and the
AEAD ciphertext existing.

This produces a `SelfDestructingMessage`: AEAD ciphertext (fine to hold
in an ordinary, non-zeroize buffer — it's useless without the key) plus
the zeroize-guarded `OKM`. Rendering the message means decrypting that
AEAD ciphertext on demand with `OKM`, which still exists only until
expiry/read fires.

---

## 3. Clock trust — what's mitigated, what's explicitly not

Phase 3's own threat model (§3.4, physical-adversary section to be added
in this sub-phase) assumes **the adversary has the device**. That
directly includes the ability to change the device's wall clock. A naive
expiry check (`SystemTime::now() >= expiry_at`) is trivially defeated by
setting the clock backward before that comparison ever runs.

**Primary mechanism (implemented): monotonic-clock-anchored expiry.**
The expiry deadline is computed once, at message-processing time, as
`Instant::now() + expiry_window` and enforced by a background timer
(`tokio::time::sleep_until` on that `Instant`). `Instant` is not derived
from the wall clock and is not affected by changing the OS date — this
defeats the "set the clock back" attack **for as long as the process
keeps running**.

**Secondary mechanism (implemented): rollback-detection watermark for
process restarts.** A real client needs to survive being closed and
reopened before a message expires, which `Instant` alone can't do (it's
meaningless across a process restart). To recover elapsed time across a
restart without blindly trusting the wall clock: periodically persist a
`(wall_clock_now, monotonic_now)` watermark pair while the process runs.
On startup, compare the new wall clock against the last persisted
watermark's wall clock:
- If `new_wall_clock < last_watermark.wall_clock`: the clock was rolled
  back. **Fail closed** — treat every pending self-destructing message as
  already expired (zeroize immediately, refuse to render) rather than
  trust a clock that's provably gone backward. This is the brief's
  explicit fail-closed requirement applied to clock integrity itself.
- Otherwise: elapsed wall time since last watermark is trusted for
  restart-recovery purposes, and a fresh monotonic timer picks up from
  there for the remainder of the expiry window.

**What this does NOT solve, stated plainly rather than implied:**
- **A rooted/jailbroken device can manipulate the watermark file itself,
  not just the OS clock.** The rollback-detection mechanism only defeats
  an adversary who can change the system date through ordinary means
  (settings UI, `date -s`) but cannot also rewrite arbitrary app storage.
  A fully-privileged local attacker can advance the persisted watermark
  to match a rolled-back clock, defeating detection. This matches the
  brief's own pre-written example limitation almost exactly and is
  recorded as such in the README.
- **A device that's powered off, imaged, or never allowed to run the app
  process again is not defended against at all.** No user-space
  mechanism — monotonic clock, watermark, or otherwise — can fire if the
  process never executes. An adversary who seizes the device before
  expiry and never lets the app launch again gets a device that's frozen
  exactly at the moment of seizure, self-destruct or not.
- **Network time cross-check (mentioned as an option in the brief) is
  deferred, not implemented in 3A.** The relay could supply a
  harder-to-locally-tamper-with reference timestamp, but that adds an
  online-dependency this project's offline/D3 goals argue against making
  load-bearing for a core safety property. If a future sub-phase wants
  it, it should be an additional signal the watermark check consults
  when available, not a requirement for self-destruct to function at all
  offline.

---

## 4. Zeroize discipline

Every struct holding key material or transiently-held plaintext:

| Value | Type | Zeroized when |
|-------|------|----------------|
| `content_key_seed` (IKM) | `Zeroizing<[u8; 32]>` | Immediately after HKDF-Expand produces `OKM` — the seed is never needed again |
| `OKM` (derived key) | Custom struct, `#[derive(Zeroize, ZeroizeOnDrop)]` | On expiry fire, on read-trigger fire, or on `Drop` |
| Plaintext held between `decrypt()` and AEAD re-encryption | `Zeroizing<Vec<u8>>` | Immediately after AEAD encryption completes |
| Plaintext held between AEAD decryption (on render) and hand-off to the UI layer | `Zeroizing<Vec<u8>>` | Immediately after hand-off, or on the same expiry/read trigger |

**Residual, documented risk:** the `hkdf` crate's internal `Hkdf` state
(the PRK) is not independently wrapped in zeroize by this design — it's
a RustCrypto crate we consume, not something PARDA controls the internals
of. Its lifetime is bounded to the single function call that derives
`OKM` (Rust drops it at scope exit, `finalize_into` consumes `self`), which
minimizes but does not eliminate the exposure window. This is recorded
here rather than silently assumed away — matching the brief's own
standard of documenting what's mitigated vs. what's merely reduced.

Every code path between `decrypt()` returning plaintext and the AEAD
ciphertext existing will be audited for accidental copies (an extra
`.clone()`, an intermediate `format!()`, a `tracing::debug!` that
accidentally interpolates plaintext) as part of implementation, not
assumed correct because the types are right.

---

## 5. Memory-forensics test plan

Two complementary tests, because a full-process memory scan and a
targeted address check prove different things and neither alone is
sufficient:

1. **Direct address re-read (portable, both CI platforms).** Capture the
   raw pointer/address of the buffer holding `OKM` (or the plaintext)
   before triggering zeroize. Trigger the erasure. Immediately —
   synchronously, before any other allocation can plausibly reuse that
   memory — read the same address again via `unsafe` and assert the
   canary bytes are gone. This is the same class of technique the
   `zeroize` crate's own test suite uses to defeat compiler
   optimizations that would otherwise elide "useless" writes to
   about-to-be-dropped memory. It proves *this specific allocation's
   bytes changed*, which is the literal claim "deleted means
   overwritten" makes.
2. **Broader process-memory scan (Linux only, `#[cfg(target_os =
   "linux")]`, runs in the `ubuntu-latest` CI leg).** Write a unique,
   high-entropy canary as the secret's value, confirm it's actually
   findable by scanning `/proc/self/mem` against `/proc/self/maps`'
   readable regions (a sanity check — a test that can't find a value
   that should be there is worthless), trigger zeroize, and assert the
   canary is no longer found anywhere in scanned memory. This is closer
   to literal "scan process memory," and is Linux-only because Windows'
   equivalent (`ReadProcessMemory`/`VirtualQueryEx` against the
   process's own handle) is a larger, separate piece of platform-specific
   `unsafe` code; if this sub-phase's timeline allows, the Windows
   equivalent can be added, but it is **not** planned as a 3A blocker —
   test 1 already runs on both platforms and proves the core claim.

**Explicitly out of scope for these tests (this is Sub-Phase 3C's job):**
swap/pagefile recovery, cold-boot RAM extraction, and `mlock`-verified
non-pageability. Test 1 and 2 above prove the key is gone from *live,
resident* process memory — they say nothing about whether a copy was
paged to disk before zeroize ran. That's a distinct claim 3C's own
forensic-recovery test will make.

---

## 5a. Implementation addendum: the memory-forensics test caught a real design flaw, not just a test bug

While implementing §5's technique 1, the initial version — capture a raw
pointer to the key bytes, call `expire_now()` (which did
`*guard = None` directly), re-read the same pointer — failed
intermittently with clearly non-zero, pointer-shaped garbage instead of
the expected zeros. This was **not a false alarm from a flawed test**:
`Option<T>` transitioning `Some → None` runs `T`'s `Drop` (so the
volatile zero-write genuinely happens), but once the `Option`'s *shape*
has changed to `None`, nothing in the language keeps the former payload
region meaningful — even inside a still-live heap allocation, the
compiler is free to treat those bytes as available for something else
once they stop being part of any well-defined value. The zeroize wrote
zeros; reading them back through a stale pointer captured before the
shape change is not guaranteed to see them.

**Fix:** `erase()` (the shared function `expire_now()` and the expiry
timer both call) now zeroizes the key explicitly *while it is still
`Some`*, then clears the slot to `None` as a separate step:

```rust
fn erase(slot: &Mutex<Option<DerivedKey>>) {
    let mut guard = slot.lock().unwrap();
    if let Some(key) = guard.as_mut() {
        key.zeroize();
    }
    *guard = None;
}
```

This is the same pattern the `zeroize` crate's own integration tests use
to verify themselves (read through a live, type-stable binding
immediately before/after the write, never a pointer captured across a
value's shape changing) — `protocol/src/self_destruct.rs`'s
`#[cfg(test)] mod tests` now does the same. This is recorded here
because it's exactly the kind of thing the brief warned about:
"distinguish rigorously between 'the deletion function ran' and 'the
plaintext is actually unrecoverable.'" The first version of this code
*did* run a real, volatile zeroize — and the test still caught that the
overall erasure sequence wasn't provably correct end-to-end. That's the
test doing its job.

## 5b. Sub-Phase 3B addendum: read-triggered destruction (implemented)

Sub-Phase 3B adds `SelfDestructingMessage::seal_read_triggered` and makes
`open()` mode-aware. No new design note was required for this
sub-phase (the brief only mandated one for 3A's KDF/clock-trust
decisions), but the key implementation decision is recorded here since
it lives in the same module and same file.

**The atomicity requirement — "not renderable a second time, including
against a force-kill mid-render" — is satisfied structurally, not by
timing.** `open()` performs the AEAD decrypt and, for a read-triggered
message, the key erasure *inside the same held `Mutex` lock*, before
returning anything to the caller:

```rust
pub fn open(&self) -> Result<Zeroizing<Vec<u8>>> {
    let mut guard = self.key.lock().unwrap();
    let plaintext = { /* decrypt using guard.as_ref() */ };
    if self.mode == DestructMode::ReadTriggered {
        if let Some(key) = guard.as_mut() { key.zeroize(); }
        *guard = None;
    }
    Ok(Zeroizing::new(plaintext))
}
```

Two consequences follow directly from this shape, not from any
scheduling assumption:

1. **No caller ever observes "decrypted but key still live."** The lock
   is held across both steps, so a concurrent second caller blocks on
   the mutex until the first caller's `open()` — decrypt *and* erase —
   has fully completed. `protocol/tests/self_destruct_tests.rs::test_read_triggered_concurrent_opens_only_one_succeeds`
   proves this directly: 32 tasks released simultaneously via a
   `tokio::sync::Barrier` all race to `open()` the same message; exactly
   one ever succeeds, deterministically, every run (not "usually" —
   the mutex makes this a structural guarantee, not a timing-dependent
   one).
2. **A literal "kill the OS process mid-render, then check on restart"
   test does not apply to this primitive as scoped.** Everything here —
   the derived key, the AEAD ciphertext, the `Arc<Mutex<..>>` — is
   in-memory only; a real process kill destroys all of it, leaving
   nothing to inspect afterward. The brief's actual concern — "the
   plaintext must not be renderable a second time after the triggering
   read" — is fully addressed by the atomicity argument above: since
   `open()` only ever returns *after* erasure is complete, there is no
   window between "caller has plaintext" and "key still exists" for a
   kill (of the *caller*, e.g. a UI task, not the whole process) to land
   in. A test that persists the ciphertext and separately persists
   erasure state across a real restart is Sub-Phase 3D's SQLCipher-store
   boundary work, not this sub-phase's.

**Guarantee separation, restated precisely (per the brief's explicit
requirement not to let the two modes blur together):**

| | `TimeBound` | `ReadTriggered` |
|---|---|---|
| Erased when | monotonic timer fires at `timestamp_ms + expiry_window` | first successful `open()` |
| Erased if never read | yes | **no — stays readable indefinitely** |
| Erased if read multiple times before expiry | no (each read is independent until expiry) | n/a — first read erases it |
| Depends on | `clock_guard` (cross-restart rollback detection) | nothing time-related at all |

## 8. Sub-Phase 3C addendum: swap avoidance and the forensic-recovery test

### Design: `mlock`/`VirtualLock`, applied to the derived key only

`protocol/src/secure_memory.rs` wraps `mlock`/`munlock` (Unix, via
`libc`) and `VirtualLock`/`VirtualUnlock` (Windows, via `windows-sys`) —
raw OS syscall FFI, not a cryptographic primitive, so this doesn't
implicate the no-custom-crypto constraint. `DerivedKey`
(`self_destruct.rs`) was changed from an inline `[u8; 32]` to a boxed
`Box<[u8; 32]>` specifically so it's its own dedicated heap allocation —
`mlock` operates at page granularity, and locking a page shared with
unrelated `Arc`/`Mutex` bookkeeping would be harder to reason about and
verify, even though it wouldn't be *incorrect* (over-inclusive locking
isn't a security bug, just imprecise). The key is locked in
`DerivedKey::new` (called from `derive_key`, immediately after HKDF
writes into the box — see that function's comment on why the window
before locking can be shrunk but not eliminated) and unlocked in `Drop`,
after zeroizing.

**Deliberately scoped to the derived key, not every buffer that ever
touches plaintext:**

- The HKDF `seed` (`Zeroizing<[u8; 32]>`) is stack-allocated and
  short-lived (exists only for the duration of `derive_key`). Locking
  stack memory is unusual and not obviously beneficial — stack pages are
  constantly reused by the same thread's other local variables as the
  call stack grows and shrinks, so there's no stable, meaningful
  "region" to lock the way there is for a dedicated heap allocation, and
  the exposure window is already much smaller than the derived key's
  (which lives for the whole expiry window or until read).
- The plaintext `Zeroizing<Vec<u8>>` returned by `open()` is zeroized on
  drop but **not** locked. A caller holding it during a brief render
  window has a swap-exposure gap this sub-phase does not close — the
  brief's literal requirement is "any buffer holding live key material,"
  and the derived key is that; extending the same treatment to every
  plaintext copy is a reasonable follow-up, not implemented here.
- The AEAD ciphertext (`self.ciphertext: Arc<Vec<u8>>`) is not locked —
  it's useless without the key, same reasoning as its existing doc
  comment.

### Verification: OS-reported accounting, not just a non-error return code

Per the brief's explicit instruction not to "just call the API and
assume it worked": `secure_memory::locked_byte_count()` reads
`/proc/self/status`'s `VmLck` field on Linux and compares it before/after
locking, so the test asserts the **OS's own bookkeeping** actually
changed, not merely that `mlock()` returned 0.
`test_lock_increases_os_reported_locked_byte_count` and
`test_locked_region_accounting_survives_memory_pressure`
(`protocol/src/secure_memory.rs`) cover this. Windows has no equivalent
low-friction per-process "locked byte count" API; verification there is
limited to `VirtualLock`'s own return code plus its documented
working-set-quota failure mode — recorded as a real asymmetry between
platforms, not glossed over.

**The memory-pressure test's claim is narrower than "we proved swapping
was avoided," stated precisely:** it proves the lock's OS-reported
status survives a large volume of unrelated allocation/write activity
(256 MiB, genuinely touched, not just reserved) happening around it —
not that any of that pressure actually forced the OS to swap something
to disk (which depends on the runner's total RAM and configuration, not
controllable or portably assertable from within the test). Directly
inspecting swap contents for the literal absence of key bytes would need
root and a deliberately swap-starved environment; that's out of scope
for a portable CI job.

**mlock failure is expected in some environments and is not a test
failure.** `RLIMIT_MEMLOCK` in constrained containers, or Windows
working-set quota exhaustion, can make locking fail legitimately. Every
test that depends on locking succeeding checks the result and skips its
assertion (with a printed reason) rather than treating failure as a bug
— the *code's* handling of that failure (log at `warn`, keep the key
usable) is what's actually under test, not "locking always succeeds
everywhere."

### The forensic-recovery capstone test

`protocol/tests/forensic_recovery_tests.rs` is the sub-phase's actual
deliverable, per the brief's own framing ("this test is the actual point
of the entire sub-phase — treat it as more important than the feature
code itself"). It runs as an external, public-API-only test (so it
proves **plaintext** is unrecoverable, not key bytes specifically — the
key-bytes claim is proven separately by the private-field-access tests
inside `self_destruct.rs`) against both destruct modes:

1. Seal a distinctively-tagged plaintext.
2. Confirm it's genuinely absent from process memory pre-read (only AEAD
   ciphertext should be resident) and genuinely present right after a
   read — both are sanity checks on the scan technique itself, not the
   claim under test.
3. Trigger destruction (expiry or the triggering read).
4. Simulate seizure: scan process memory again (Linux:
   `/proc/self/mem`+`/proc/self/maps`, same technique as
   `self_destruct.rs`'s own Linux-only tests; all platforms: the public
   API — `is_expired()`, `open()` — must refuse).
5. Assert the plaintext is nowhere to be found.

**"Dump all accessible storage,"** the brief's other half of this test:
`SelfDestructingMessage` has no `Serialize` implementation and no file
I/O anywhere in its code. There is nothing on storage to recover — by
the absence of any persistence capability, not by a runtime check. This
is worth stating explicitly rather than silently relying on: a real
persistent holding area (Sub-Phase 3D) will have to enforce "never
written for a self-destructing message" at its own write path; that
property does not carry over automatically just because this sub-phase's
primitive happens not to persist anything yet.

## 9. Sub-Phase 3C addendum: mobile native-bridge audit

Per the brief: "a Dart-side `zeroize` call is worthless if the
Kotlin/Swift layer already made an unmanaged copy." Findings from
actually reading `mobile/android/app/src/main/kotlin/com/parda/app/SignalPlugin.kt`,
`mobile/lib/crypto/signal_bridge.dart`, and
`mobile/lib/services/session_service.dart`, rather than assuming:

1. **No self-destruct integration exists on mobile at all.** `SignalPlugin.kt`'s
   method channel (`generateIdentity`, `encryptMessage`, `decryptMessage`,
   `hasSession`, …) implements Phase 1 X3DH/Double-Ratchet only. There is
   no self-destruct-specific native code to audit yet — wiring
   `self_destruct` into the mobile layer is Sub-Phase 3D's "application
   layer" work, not something that exists to hardened now. This section
   audits the *existing* plaintext-handling discipline, since the same
   gap will apply the moment self-destruct is wired in.
2. **Real finding, fixed:** `handleEncryptMessage` and
   `handleDecryptMessage` both held plaintext in a plain JVM `ByteArray`
   crossing the MethodChannel boundary, with nothing clearing it —
   subject only to GC, not deterministic erasure. Fixed by adding
   `java.util.Arrays.fill(plaintext, 0)` in a `finally` block after the
   bytes are no longer needed in each handler. **This Kotlin change has
   not been runtime-verified against a real Flutter build** — there is
   no Android/Flutter toolchain available in the environment this change
   was made in. The reasoning it relies on (`MethodChannel.Result.success()`
   synchronously encodes the value via `StandardMethodCodec` before
   returning, so clearing the source array afterward doesn't corrupt
   what's already been sent) is standard, well-documented Flutter
   platform-channel behavior, but "reasoned to be correct" and "verified
   correct" are different claims — this one is the former. Run the
   mobile app's encrypt/decrypt flow before trusting this change in
   production.
3. **Deeper, unresolved finding: the Dart layer converts plaintext to a
   `String`.** `session_service.dart` does
   `final body = utf8.decode(plaintextBytes);` — Dart's `String` type has
   no mutable, user-accessible backing storage; there is no API to
   overwrite a `String`'s memory the way `Uint8List.fillRange` or Rust's
   `zeroize` can for byte buffers. **This means the current mobile
   architecture cannot provide a "provably erased" guarantee once
   plaintext is turned into a `String`, full stop, regardless of any
   zeroize discipline applied earlier in the chain.** Wiring self-destruct
   into the mobile UI (Sub-Phase 3D) will need to keep plaintext as bytes
   all the way to the rendering widget, or explicitly accept and document
   this as an unsolved gap for the mobile client specifically. Not fixed
   here — recorded because finding it and staying silent would be worse
   than not looking.
4. **`SignalBridge`'s Dart-side `Uint8List` (`signal_bridge.dart`,
   `decryptMessage`/`encryptMessage`) is not cleared either.** Lower
   priority than finding 3 (a `Uint8List` at least *could* be cleared
   with `fillRange`, unlike a `String`), but still open.
5. **No iOS counterpart exists.** `mobile/ios/` has no `SignalPlugin.swift`
   or equivalent — there is nothing to audit on that platform because it
   hasn't been built yet. This is a pre-existing gap, not one introduced
   by Phase 3; recorded here because the brief explicitly asks about "the
   native bridge... and its iOS counterpart," and claiming an audit of
   something that doesn't exist would be dishonest.
6. **Not addressed:** `protocolStore` (the in-memory session/identity key
   store on the Android side) has no explicit clearing on plugin detach,
   app backgrounding, or low-memory conditions. Pre-existing since Phase
   1, out of scope for a "self-destruct native-bridge audit" specifically,
   but adjacent enough to note rather than let the audit imply everything
   else was checked and found fine.

## 10. What's deferred past 3A/3B/3C (not attempted now)

- **Where a self-destructing message's AEAD ciphertext lives between
  relay delivery and the user opening the app to read it** (i.e.
  surviving an app restart while still pending) is a storage-layer
  question that belongs with 3D's SQLCipher-store boundary work ("a
  self-destructing message must never be written to the durable
  message-history store") — 3A builds the derive/hold/expire-and-zeroize
  primitive as a standalone module and proves it in isolation; wiring it
  into a restart-surviving holding area is explicitly 3D's problem, not
  solved here.
- Read-triggered destruction and its atomicity argument are covered in
  §5b; `mlock`/swap-avoidance and the mobile native-bridge audit
  (Sub-Phase 3C) are covered in §8/§9.
- Still genuinely deferred: locking (not just zeroizing) the plaintext
  buffer `open()` returns, not just the derived key (§8); giving the
  mobile Dart layer an actual fix rather than just the finding that its
  `String`-based plaintext handling can't be provably erased (§9); an
  iOS native bridge, which doesn't exist to hardened yet (§9); and
  everything Sub-Phase 3D scopes (session-burn, CLI, REST gateway,
  SQLCipher store boundary).

---

## 11. Open questions — 3A's resolved, 3C's new

**From 3A's original review (resolved via the AskUserQuestion exchange
before implementation began):**

1. ~~Is the IKM substitution in §1 (fresh local random seed, not the
   literal Double-Ratchet key) acceptable?~~ Confirmed — implemented as
   proposed.
2. ~~Is the clock-trust mitigation in §3 the right scope for 3A?~~
   Confirmed as scoped, with network-time cross-check staying deferred.
3. ~~Default expiry window?~~ Confirmed at 5 minutes
   (`DEFAULT_EXPIRY_WINDOW`).

**New from 3C, for review before this is trusted further:**

4. §9 finding 2 (the Kotlin `ByteArray` clearing fix) is reasoned-correct
   but not runtime-verified against an actual Flutter build — there is no
   Android/Flutter toolchain in the environment this was written in.
   Should this be run through the real app before being relied upon, or
   is the reasoning (documented in §9) sufficient to proceed?
5. §9 finding 3 (Dart `String`-based plaintext can't be provably erased)
   is a real architectural constraint on whatever Sub-Phase 3D does to
   wire self-destruct into the mobile UI. Worth deciding now — e.g.
   "self-destructing message content stays as bytes/`Uint8List` all the
   way to a custom rendering widget, never becomes a `String`" — or fine
   to leave as an open design question for 3D itself to resolve?
6. §8's scope decision to lock only the derived key, not the plaintext
   `open()` returns: acceptable as the literal reading of "any buffer
   holding live key material," or should Sub-Phase 3C's definition of
   done be read more broadly to require locking plaintext too before
   it's considered complete?

---

## 12. Sub-Phase 3D addendum: application layer

### Session-burn: the same honesty standard applied to a harder case

`InMemorySignalProtocolStore::burn_session` (`protocol/src/store.rs`) and
`SessionManager::burn_conversation` (`protocol/src/session.rs`) implement
"burn this conversation." Investigating what erasure guarantee this could
honestly claim turned up something worth treating as seriously as §1's
Double-Ratchet-key finding: reading `libsignal-protocol` v0.66.0's own
source (`rust/core/src/curve.rs`), `PrivateKey` is

```rust
enum PrivateKeyData { DjbPrivateKey([u8; 32]) }

#[derive(Clone, Copy, Eq, PartialEq, derive_more::From)]
pub struct PrivateKey { key: PrivateKeyData }
```

— `Copy`, with no `Zeroize`, no custom `Drop`. `SessionRecord` has
neither either. This means `burn_session` **cannot** make the same
"provably erased from live memory" claim `self_destruct::erase` makes:
libsignal's own internals may hold an unknown, uncountable number of
implicit stack/register copies of this key material, and nothing in
PARDA's code can see or overwrite them without forking or patching
libsignal — the same no-custom-crypto risk §1 already declined to take
for the same underlying reason.

**Decision: implement `burn_session` for what it can honestly guarantee
— the session record and trusted-identity entry are removed from
PARDA's own store, so the conversation is unusable through the normal
API, tested and real (`protocol/tests/session_burn_tests.rs`, 4/4
passing) — and document the narrower scope explicitly everywhere the
function is described, rather than let a reader assume it matches
`self_destruct`'s guarantee by proximity.** This is precisely the
brief's own standard applied to a case where a full fix isn't available:
say what's true, not what would be convenient.

### Client-side SQLCipher store: write-path enforcement needed a wire-format addition

Sub-Phase 3B's `read_triggered_destruct` concept had no wire
representation — `self_destruct_at: Option<u64>` can express "expires at
T" but not "expires on read, no fixed T." Enforcing
`parda-client-store`'s "never persist a self-destructing message"
boundary for *both* modes therefore required adding
`MessageEnvelope::read_triggered_destruct: bool` (`#[serde(default)]`,
additive, matches the existing `version` field's backward-compatibility
pattern — old envelopes deserialize as `false`). `LocalMessageStore::store_message`
checks `self_destruct_at.is_some() || read_triggered_destruct` and
refuses before any SQL runs — never a partial write, tested explicitly
(`test_refusal_does_not_partially_write_anything`).

### REST gateway: honest about not being a new security boundary

`parda-gateway` doesn't depend on the `parda-relay` crate — it's a
genuine HTTP proxy, calling a relay (real or the CLI's stub) exactly the
way any external client would. This was a deliberate choice for two
reasons: it keeps the gateway's own build free of the vendored-SQLCipher
requirement (relevant before the Perl fix below, though the crate would
stay this shape regardless), and it's a more honest architectural
match — a gateway fronting a service as a separate network hop, not
embedded library code pretending to be one. `lib.rs`'s module docs say
plainly that this crate adds an external-facing API surface, not a new
cryptographic guarantee the relay lacks — `parda-relay` was already a
dumb pipe.

### The Perl gap: fixed this session, and what fixing it revealed

Earlier `client-store`/`cli` work in this sub-phase was written against
an environment where `cargo check` couldn't even reach those crates'
own code — `rusqlite`'s SQLCipher feature needs `openssl-sys` built
first, which needs a complete Perl, and this machine only had
Git-for-Windows' minimal one. With the user's explicit go-ahead, a
portable Strawberry Perl was downloaded and put first on `PATH` for the
session (`STRAWBERRY/perl/bin`, `MSYS`-style `/c/...` path form — a
`C:/...`-style path silently breaks Bash's `:`-delimited `$PATH`, which
cost one debugging round-trip before the actual fix). Once resolved:
`parda-client-store`, `parda-relay`, and `parda-mixnode`'s dev-dependency
on the relay all compiled clean on the **first** try — no logic bugs
found in any of them. `parda-cli` needed two trivial missing-dependency
lines added to its `Cargo.toml` (`rand`, `libsignal-protocol` — used
directly in `main.rs` but only depended on transitively via
`parda-protocol`).

**Running the CLI demo for real then immediately caught a genuine,
pre-existing bug that had been latent since Phase 1**:
`DirectTransport::receive` (and `MixTransport::receive`, identical code)
deserialized the relay's `GET /v1/messages/{id}` response straight into
`Vec<MessageEnvelope>` — a bare array. The real relay
(`server/src/routes.rs::fetch_messages`) has always returned
`{"messages": [...]}`, an object. `grep -r DirectTransport` across the
whole repository, before the fix, turned up zero test files — nothing
had ever called `receive()` against a live relay over real HTTP. Fixed
by adding a small `FetchMessagesResponse { messages: Vec<MessageEnvelope> }`
deserialization target in `transport.rs` (see that file's doc comment
for the full account). This is exactly the brief's stated reason for
building the CLI early — "your fastest test harness" — borne out
concretely rather than staying a hypothetical benefit.

### What's still open after 3D

- The Kotlin `SignalPlugin.kt` fix from §9 remains unverified against a
  real build — that gap is a *different* toolchain (Android/Flutter),
  not fixed by resolving Perl, and wasn't attempted this session.
- No iOS native bridge exists (§9, unchanged).
- Self-destruct is still not wired into the mobile UI at all — 3D built
  the CLI's application layer, not the mobile one. `session_service.dart`'s
  `String`-based plaintext handling (§9 finding 3) remains an open
  architectural question for whenever that wiring happens.
- The CLI's prekey-bundle exchange is in-process, not over HTTP (see
  `cli/src/main.rs` module docs for why this scope decision was made and
  why it's a reasonable one, not a shortcut hiding a gap).
- `parda-gateway` has no auth, rate limiting, or request-shape validation
  beyond what axum's `Json` extractor gives for free on the prekey-bundle
  routes — described in its own docs as a place such things could grow,
  not a claim that they exist yet.
