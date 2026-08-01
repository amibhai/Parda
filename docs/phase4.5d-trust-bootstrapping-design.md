# Phase 4.5 / Sub-Phase 4.5D — Design Note: Unified Trust Bootstrapping

**Status:** Design reviewed prior to implementation | **Date:** 2026-08-01

This note exists because the brief requires one before touching this
sub-phase's riskiest decision — the same standard `docs/phase3-3a-self-destruct-design.md`,
`docs/phase4-4c-dead-drop-addressing-design.md`, and
`docs/phase4.5a-receive-path-design.md`/`docs/phase4.5c-dart-plaintext-design.md`
were already held to.

---

## 1. What's actually there today, read directly rather than assumed

`protocol/src/store.rs`'s `IdentityKeyStore for InMemorySignalProtocolStore`
(the trait libsignal itself calls during `process_prekey_bundle` and
`message_decrypt`) already does more than "trust everyone forever":

```rust
async fn is_trusted_identity(&self, address: &ProtocolAddress, identity: &IdentityKey, _: Direction) -> Result<bool, _> {
    Ok(self.state.borrow().trusted_identities.get(&address.to_string())
        .map(|stored| stored == identity)
        .unwrap_or(true)) // trust if unseen
}
```

This is trust-**pin**-on-first-use, not naive always-trust: the *first*
identity key ever seen for a given address is pinned, and a later
message claiming a *different* identity key for that same address is
already rejected by libsignal itself (`is_trusted_identity` returns
`false` → `SignalProtocolError::UntrustedIdentity`). What's genuinely
missing, confirmed by reading every call site (`session.rs`,
`sealed_sender.rs`, `mixnet.rs`), is what the brief names precisely:

1. **No distinction between "pinned because it's the first thing we saw"
   and "the user compared a fingerprint out-of-band and confirmed it."**
   Every peer is in exactly one bucket today. A real MITM that's
   present from the very first contact (before any pinning happens) is
   invisible to the existing mechanism — it pins the *attacker's* key
   on first use, indistinguishably from pinning the real one.
2. **No human-comparable fingerprint exists anywhere in this codebase.**
   There's nothing a user could read aloud or compare against a QR
   code.
3. **Three independent, undocumented TOFU postures**, not one: prekey
   bundle acceptance (above), sealed-sender certificate trust
   (`sealed_sender.rs`'s `CertificateAuthority` — trusts any cert
   signed by the configured root, with no per-sender pinning at all),
   and mix topology (no identity concept for mix nodes yet at all,
   beyond the static key each node is configured with). This sub-phase
   unifies the *concept* (one `Fingerprint`/`TrustLevel` model) without
   claiming to unify the *enforcement depth* — see §4.

---

## 2. Fingerprint construction — cited, not invented

**The general pattern is Signal's own published "safety number"
concept**: a fingerprint derived from both parties' long-term identity
keys, displayed as a sequence a human can read aloud or scan, compared
out-of-band (in person, over a trusted channel) before either party
marks the other "verified."

**This project does not reimplement Signal's exact algorithm.** Signal's
real safety-number construction (`libsignal`'s `Fingerprint`/`ScannableFingerprint`
types) is an iterated SHA-512 stretch (5200 rounds) over each identity
key plus a stable per-pair "version" byte, with a specific
byte-interleaving between local/remote halves — reverse-engineering
that from memory and re-implementing it by hand carries a real,
specific risk: getting one byte-order or iteration-count detail subtly
wrong produces something that *looks* like a safety number but isn't
the audited one, which is a worse outcome than plainly using a
different, simpler construction and saying so.

**Construction actually used:**

```text
Fingerprint = HKDF-SHA256(
    salt = "PARDA-Fingerprint-v1",
    ikm  = sorted(local_identity_key.serialize(), remote_identity_key.serialize()) concatenated,
    info = "PARDA-Fingerprint-v1",
    len  = 60 bytes
)
```

- **HKDF-SHA256** — the same primitive already used twice in this
  codebase (`self_destruct::derive_key`, `dead_drop::TagKey`), not a
  new cryptographic building block for a reviewer to separately audit.
- **`sorted(...)`** (lexicographic on the serialized 33-byte
  `IdentityKey` encoding) rather than "local then remote": both parties
  must compute the identical fingerprint regardless of which side of
  the conversation they're on, exactly like Signal's own safety numbers
  are symmetric. Sorting by serialized bytes is simpler and just as
  correct as Signal's local/remote-halves-interleaved approach for this
  purpose — the interleaving in Signal's real construction exists for
  their specific display format (each party's own key contributes a
  distinguishable half so a user can tell "this is roughly where my key
  shows up"), which this project's flat digit-group display doesn't
  attempt to replicate.
- **60-byte output → 12 groups of 5 decimal digits** (60 digits total,
  matching Signal's on-screen digit count, since a familiar shape is
  easier for a user to compare correctly than an unfamiliar one).
  Concretely: chunk the 60 bytes into twelve 5-byte groups, interpret
  each as a big-endian 40-bit integer, reduce mod `100000`, zero-pad to
  5 digits. This is display formatting only, not a cryptographic step —
  the security property lives entirely in the HKDF output, not the
  decimal encoding. Signal reaches its own 60 digits differently (30
  digits derived from each party's key separately, then concatenated);
  one 60-byte HKDF expansion over both keys is simpler and, since the
  two halves are not meant to be independently meaningful here, loses
  nothing this design uses. Reducing each 40-bit group mod `10^5`
  discards a fraction of a bit per group; the displayed value carries
  ~199 bits (60 × log₂10), far above any collision concern for a
  human-compared fingerprint, and the comparison itself is against the
  full stored [`Fingerprint`] bytes regardless — the digits are what a
  user reads, not what the code checks.

**Stated once, plainly: this is a deliberate, documented simplification,
not a claim of bit-compatibility with Signal's safety numbers, `libsignal`'s
`Fingerprint` type, or any other existing implementation's algorithm.**
Two PARDA users comparing fingerprints only ever compare PARDA-computed
values against each other — cross-checking against a Signal app's
safety number was never a goal and this construction makes no attempt
to support it.

---

## 3. `TrustLevel` and where it's checked

```rust
pub enum TrustLevel {
    /// No out-of-band verification has happened. This is the default —
    /// and, unchanged from today's behavior, an unverified peer is still
    /// usable: pin-on-first-use continues to apply underneath this.
    Tofu,
    /// The user compared this exact fingerprint out-of-band and
    /// confirmed it matches. From this point on, any *different*
    /// fingerprint for the same peer is a hard failure, not a silent
    /// re-pin.
    Verified,
}
```

`TrustStore` (trait + `InMemoryTrustStore`, mirroring
`clock_guard::ClockWatermarkStore`'s trait/impl split — production
callers back this with real persistent storage, exactly as that
module's docs already note for its own trait) stores, per peer ID: the
fingerprint that was verified, if any. Absence of an entry *is*
`TrustLevel::Tofu` — there is no separate boolean to fall out of sync
with the fingerprint itself.

**Enforcement is added as an explicit, opt-in check**, not a change to
`SessionManager::initiate_session`'s existing signature: a new
`trust::check_identity_against_trust_store(trust_store, peer_id, local_identity_key, remote_identity_key)`
function, and a new `SessionManager::initiate_session_verified(...)`
convenience wrapper that calls it before delegating to the existing
`initiate_session`. This is deliberate — the brief's own backward-
compatibility requirement ("an unverified conversation behaves exactly
as today") is easiest to prove true when the existing, already-tested
code path is untouched and the new one is additive. Callers that never
adopt a `TrustStore` see zero behavior change, not just "probably no
behavior change."

**A concrete case this closes that libsignal's own pinning does not,
found while designing the wiring below, not assumed:** `SessionManager::burn_conversation`
(Sub-Phase 3D, `store.rs::burn_session`) explicitly removes the
signal-level `trusted_identities` entry for an address as part of
making a burned conversation behave as if it never existed —
correct and load-bearing for that feature's own goal, but it also
means libsignal's own `is_trusted_identity` treats the *next* prekey
bundle for that address as first contact again, TOFU-pinning whatever
identity key arrives, attacker's or not. A `TrustStore` entry is
untouched by `burn_session` (it's a separate module with its own
lifetime, keyed by peer ID rather than session state) — so a
`Verified` fingerprint recorded before a burn still protects the next
`initiate_session_verified` call after one. This is the concrete reason
this sub-phase's check has to be a genuinely separate, persistent
mechanism rather than just reading libsignal's own pin state back.

**Wired into two of the three TOFU points named in §1:**

1. **Prekey bundle acceptance** (`session.rs`): `initiate_session_verified`,
   as above. A bundle whose identity key doesn't match a *verified*
   fingerprint on file fails with the new `PardaError::IdentityKeyChangedAfterVerification`
   — a distinct, specific error from libsignal's generic
   `UntrustedIdentity`, so a caller (and this sub-phase's test) can tell
   "this is a post-verification identity change," a strictly more
   alarming condition than an ordinary first-contact pin, apart from
   any other untrusted-identity cause.
2. **Sealed-sender certificate trust** (`sealed_sender.rs`): a new
   `decrypt_sealed_verified` wrapper on `SessionManager`, same shape —
   checks the recovered sender's identity key (available *after*
   `sealed_sender_decrypt` validates the certificate chain, since that's
   the earliest point the sender's identity key is authenticated at
   all) against the trust store before returning the plaintext to the
   caller.

**Mix topology (the third point) gets a data-model hook and a
documented workflow only, not enforcement** — matching the brief's own
explicitly lighter bar for this one: `TrustStore` is keyed by an opaque
`peer_id: &str`, which a caller is free to populate with a mix node's
public key fingerprint identifier instead of a conversation peer's; the
same `Fingerprint::compute` function works unchanged for "compare my
view of mix node X's key against what I verified out-of-band." No
mixnode-specific call site invokes this in this sub-phase — full
UI/CLI flow for verifying a mix node's identity is out of scope, and
`docs/THREAT_MODEL.md` §3.6 states this as a documented gap, not an
implemented control.

---

## 4. What this proves, and what it doesn't

**Provable, and tested (§5):** an active MITM that substitutes an
attacker's identity key *before* the user ever compares a fingerprint
succeeds exactly as today (TOFU pins whatever key arrived first — no
regression, no new false claim of protection at first contact, which
matches the fundamental limit of *any* TOFU scheme, Signal's included).
An active MITM that substitutes an attacker's identity key *after* the
user has compared fingerprints and marked the peer `Verified` is
detected and rejected — `PardaError::IdentityKeyChangedAfterVerification`,
not a silent re-pin.

**Not provable, stated directly:** this sub-phase does not build the
out-of-band comparison UI itself (no QR scan flow, no "tap to confirm
match" screen) — `TrustStore::record_verified` is called directly by
tests and would be called by a future UI layer once one exists; the
*mechanism* is complete and tested, the *user-facing verification
flow* is not part of this sub-phase's scope, matching how the mobile
UI itself (Sub-Phase 4.5B/C) is scoped to what actually got built and
verified this session, not a hypothetical future screen.
