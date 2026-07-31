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

## 6. What's deferred past 3A (not attempted now)

- **Where a self-destructing message's AEAD ciphertext lives between
  relay delivery and the user opening the app to read it** (i.e.
  surviving an app restart while still pending) is a storage-layer
  question that belongs with 3D's SQLCipher-store boundary work ("a
  self-destructing message must never be written to the durable
  message-history store") — 3A builds the derive/hold/expire-and-zeroize
  primitive as a standalone module and proves it in isolation; wiring it
  into a restart-surviving holding area is explicitly 3D's problem, not
  solved here.
- Read-triggered destruction (3B), atomicity against a force-kill race
  (3B), `mlock`/swap-avoidance (3C), and the mobile native-bridge audit
  (3C) are unaddressed by this note on purpose — each gets its own design
  attention when its sub-phase starts, per the brief's own sequencing.

---

## 7. Open questions for review before implementation

1. Is the IKM substitution in §1 (fresh local random seed, not the
   literal Double-Ratchet key) acceptable, given the DR key isn't
   reachable without reopening the no-custom-crypto constraint?
2. Is the clock-trust mitigation in §3 (monotonic timer + persisted
   rollback-detection watermark, fail-closed on detected rollback, with
   the rooted-device and powered-off-device gaps documented rather than
   solved) the right scope for 3A, or should network-time cross-check be
   pulled forward from "deferred" into this sub-phase?
3. Default expiry window: this note doesn't propose one yet. Signal's own
   disappearing-messages feature defaults are one reference point, but
   PARDA's default should be picked deliberately, not copied — what
   should it be, and should there be a minimum/maximum enforced bound?
