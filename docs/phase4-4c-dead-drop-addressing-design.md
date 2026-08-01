# Phase 4 / Sub-Phase 4C — Design Note: Anonymous Dead-Drop Addressing

**Status:** Design reviewed prior to implementation (per this phase's plan;
see `resilient-tumbling-ocean.md`) | **Date:** 2026-08-01

This note exists because the Phase 4 brief explicitly requires it: the
dead-drop addressing scheme is "the phase's central cryptographic design
problem" and must be reviewed before code exists, the same standard
`docs/phase3-3a-self-destruct-design.md` was held to for the self-destruct
KDF and clock-trust decisions. Two things here follow that note's precedent
directly — a fresh, purpose-dedicated secret instead of reaching into
inaccessible protocol internals (§1 below, same reasoning as that note's §1),
and a mitigation chosen and justified rather than left maximally strong at
any cost (§3, same "narrower than the ideal, stated precisely" posture as
that note's §3 on clock trust).

---

## 1. What key material anchors the address derivation

**Requirement:** a bundle's storage address must be derivable by sender and
intended recipient (so both can compute where a message will be, and where
to look for one), but must not reveal recipient identity to a carrier node
or to any other party observing the address.

**Not the Double-Ratchet session state.** Following the exact precedent of
`self_destruct` design note §1: `SessionManager::decrypt()`/`encrypt()`
(`protocol/src/session.rs`) never surface libsignal's internal per-session
ratchet key material through its public API (confirmed there by reading the
pinned `v0.66.0` source). Reaching for it would mean forking or
reimplementing libsignal's decrypt path — the same no-custom-crypto risk
this project has already declined twice (self-destruct's KDF, session-burn's
erasure claim). Dead-drop addressing needs its own, separate answer.

**Not the Signal identity key either.** `LocalIdentity::identity_key_pair`
(`protocol/src/identity.rs`) is already used for X3DH and XEdDSA signing.
Reusing it for a second, unrelated ECDH (address derivation) is exactly the
kind of cross-protocol key reuse this project's own precedent avoids by
generating a fresh, purpose-dedicated secret instead wherever a genuinely
separate guarantee is needed (self-destruct's HKDF seed is a fresh `OsRng`
draw, not a reused key, for the identical reason).

**Design decision: a dedicated, purpose-only X25519 keypair per
conversation.**

```
(dead_drop_priv, dead_drop_pub) = X25519 keypair, generated once per peer
                                   relationship, at the same time as (and
                                   alongside) prekey-bundle enrollment
```

Exchanged via one new, additive field on the existing prekey-bundle upload
path (`server`'s `/v1/keys/{user_id}`) — the same Trust-On-First-Use posture
this project already accepts for prekey bundles and sealed-sender
certificates (`docs/THREAT_MODEL.md` §3.5), not a new trust assumption. Once
both sides have exchanged `dead_drop_pub` keys (piggybacked on the X3DH
handshake that already happens before any messages are exchanged), each
computes:

```
shared  = X25519(dead_drop_priv_local, dead_drop_pub_remote)   // x25519-dalek,
                                                                 // already a
                                                                 // dependency
tag_key = HKDF-Extract(salt = None, IKM = shared)               // RFC 5869,
                                                                 // hkdf crate,
                                                                 // same
                                                                 // pattern as
                                                                 // self_destruct::derive_key
```

Both sides derive the identical `tag_key` (standard ECDH symmetry — the same
property X3DH itself relies on). `tag_key` is never transmitted and is used
for nothing except address derivation below — not message content, not
self-destruct. This mirrors self-destruct's own reasoning almost exactly:
address derivation is a materially different concern from message
confidentiality (it needs to be computable by *both* parties without either
one transmitting it, whereas self-destruct deliberately needed a
*non-shared*, purely local secret) — the shape of the fix differs, but the
underlying principle ("generate a fresh, purpose-dedicated secret rather
than reach into another protocol's internals or reuse a key across
purposes") is the same one already established.

---

## 2. Address derivation: a per-message counter, not wall-clock time

**Requirement:** a concrete, per-message address, derivable identically by
both sides, that changes from message to message (so a carrier can't link
a run of addresses back to one relationship just by watching how many
distinct addresses a given endpoint uses).

**Not wall-clock epoch.** An obvious construction would bucket addresses by
time window (`epoch = floor(now / window)`, an approach several deployed
systems use). Rejected here for a specific, citable reason: this project's
Phase 3 clock-trust work (`self_destruct` design note §3,
`docs/THREAT_MODEL.md` §3.4) already documents, in detail, that a
device-seizure adversary can manipulate the wall clock, and that the
project's own mitigations for that (monotonic timers, rollback-detection
watermarks) are themselves imperfect. Anchoring address derivation to wall
time would import that same unsolved category of gap into a *new* place
(an attacker who can skew a device's clock could shift which addresses it
computes) for no benefit — a counter avoids the whole problem.

**Design decision: monotonically incrementing per-peer counter**, the same
idea Double Ratchet already applies to message keys via its skipped-message
window (per-conversation message numbering, with a bounded lookahead to
tolerate reordering/loss) — applied here to *addresses* instead of
*decryption keys*.

```
address_n = HKDF-Expand(tag_key,
                         info = b"PARDA-Phase4-DeadDropAddress-V1" || n (8 bytes, BE),
                         L = 32)
```

The sender increments its local `n` once per dead-drop message composed for
that peer (a monotonic counter, persisted the same way session state
already is — not itself a new trust assumption, since a counter that's lost
or rolled back only ever causes a missed/duplicate *address*, recoverable by
the window mechanism below, not a security failure the way a self-destruct
clock rollback is). The recipient, deriving identically, doesn't know the
sender's exact current `n` in real time (no synchronization message exists,
by design — that would leak activity metadata to the mesh), so it polls a
**forward window** of upcoming values (`n_last_claimed + 1 ..=
n_last_claimed + WINDOW`) rather than only the single next expected one,
tolerating reordering and loss the same way Double Ratchet already tolerates
skipped message keys.

---

## 3. Retrieval-pattern mitigation: decoy queries, chosen and justified

**The gap, stated precisely:** even with a blinded address, a carrier that
logs "who asked for which address, when" can build a correlation graph over
polling behavior alone — this is the well-known access-pattern leakage
problem private-messaging research treats as a first-class concern distinct
from content/address confidentiality (see Adam Langley's *Pond*, which used
a PIR-queried "dead drop" numeric identifier for exactly this reason, and
Cheng et al., "Talek: Private Group Messaging with Hidden Access Patterns,"
ACSAC 2020 / IACR ePrint 2020/066, which formalizes "access sequence
indistinguishability" as the target property). **Full PIR (Talek's own
approach) is explicitly out of scope here** — it requires multiple
non-colluding servers and either lattice-based homomorphic schemes or
distributed point functions, which is itself new, unaudited cryptographic
machinery this project's no-invented-cryptography constraint would flag
immediately, and is a poor fit for a single-hop, intermittently-connected
mesh carrier model in the first place (Talek assumes a small set of
always-on servers, not an arbitrary nearby phone). The brief's own menu for
this sub-phase is narrower and was designed with that in mind: "tag
rotation, decoy/dummy retrieval queries, or batched polling — pick one,
justify it, and test."

**Design decision: decoy queries**, modeled directly on a pattern this
codebase has already implemented and already tested —
`mixnode/src/cover_traffic.rs`'s Loopix-style drop-cover traffic
(Piotrowska et al., "The Loopix Anonymity System," USENIX Security 2017,
already cited in `docs/THREAT_MODEL.md` §6). Every real poll for
`address_n` is accompanied by `k - 1` freshly-generated random 32-byte decoy
addresses. Because every real address is itself an HKDF output (uniformly
distributed, 32 bytes), a decoy drawn from `OsRng` is computationally
indistinguishable from a real one to anyone without `tag_key` — there is no
format tell the way there might be with, e.g., a structured or
short-numeric identifier. This reuses a design already validated in this
codebase rather than introducing a new mitigation family, which is worth
weighing on its own: `mixnode`'s cover traffic already proves out the
"dummy traffic indistinguishable in format from real traffic, measured via
a permutation test" methodology this section reuses below.

**Why not the other two menu options, briefly:** tag rotation alone (§2
already rotates addresses per message) doesn't hide *which* address in a
polled batch was the real one on any given poll — it only prevents the
*same* address from being reused, a different property. Batched polling
(querying on a fixed schedule regardless of whether there's anything new)
reduces *timing* correlation but does nothing about *which address in the
batch* was real, the same gap decoys are chosen specifically to close;
combining both would be stronger still and is noted as a natural follow-on,
not attempted this phase to keep the mechanism under test single-variable.

**Measured, not claimed.** `mesh/tests/retrieval_pattern_tests.rs`
implements a logging-carrier adversary with full visibility into every
`(observed_query_address, polling_round, session)` tuple across many
simulated conversations and polling rounds, and attempts to cluster queries
back to the correct conversation via co-occurrence/timing correlation — the
same permutation-test family `mixnode/tests/timing_correlation_tests.rs`
already uses for the analogous mix-network claim. It reports the
adversary's top-1 linkage accuracy at `k = 1` (baseline, no decoys) versus
several `k > 1` settings, as a concrete number the reviewer can check
against the test output, not a qualitative "harder to correlate" claim.
**This is an empirical result bounded to the tested scale and adversary
model** (a single non-colluding logging carrier; a carrier that colludes
with every other carrier a device ever polls through, across every
rotation, is a strictly stronger adversary this mitigation does not claim
to defeat — see `docs/THREAT_MODEL.md` §3.7 for the precise statement),
matching exactly how §3.6 of the threat model already scopes the
mix-network timing-correlation result.

---

## 4. Envelope wiring

One new, additive field on `MessageEnvelope`:

```rust
#[serde(skip_serializing_if = "Option::is_none")]
pub dead_drop_address: Option<[u8; 32]>,
```

`#[serde(default)]`-equivalent via `Option` + `skip_serializing_if`, the
same backward-compatible pattern `version`, `self_destruct_at`, and
`read_triggered_destruct` already established — an envelope composed by an
older build simply has `None` here and is ignored by
`DirectTransport`/`MixTransport`, exactly as `self_destruct_at` is ignored
by a build that predates Phase 3. `MeshTransport` is the only transport
that reads this field. A message is composed once; which transport
eventually carries it (direct, mix, or mesh) doesn't change its shape — the
brief's explicit requirement.

---

## 5. Self-destruct interaction

A dead-dropped bundle sitting on an untrusted carrier for an extended
period is exactly Phase 3's scenario. `mesh/src/bundle.rs::wrap` already
sets the BPv7 primary block's `lifetime` from
`MessageEnvelope::self_destruct_at` when present (`docs/phase4-...` — see
that module's doc comment), so a carrier's own TTL bookkeeping
(`mesh/src/relay.rs::sweep_expired`) purges the bundle no later than the
message's own declared expiry, independent of what the sending device does
with its local copy. Two cases, both required to behave correctly and both
covered by `mesh/tests/expiry_tests.rs`:

- **Expires before ever being picked up:** every carrier holding a copy
  purges it on its next `sweep_expired` pass once simulated time crosses
  the deadline; there is no retry, no re-request, no path back to
  deliverability — permanently undeliverable, per the brief's explicit
  requirement.
- **Mesh latency delays delivery past the deadline:** identical outcome to
  the above, not a race that sometimes succeeds — a bundle that would
  arrive after `self_destruct_at` is purged by the last carrier holding it
  before the recipient ever sees it, and even in the edge case where
  delivery and expiry are simulated to land in the same tick, the
  recipient's own `SelfDestructingMessage::seal` call (which independently
  checks `self_destruct_at` against its own monotonic clock) refuses to
  render an already-expired message regardless of what the mesh delivered.

---

## 3a. Addendum: what decoys actually cover, found while building the measurement in §3

Building `mesh/tests/retrieval_pattern_tests.rs` surfaced a real distinction
that the original §3 text glossed over by not stating it explicitly enough:
**decoys defend a *within-batch* question, not a *cross-time* one, and these
are genuinely different properties.**

- **Within one poll batch, in isolation:** an adversary who observes a single
  `build_poll_set` output (`k` addresses, exactly one real) cannot identify
  which one is real with better than `1/k` accuracy, because a decoy and a
  real address are drawn from computationally indistinguishable
  distributions (fresh `OsRng` bytes vs. an HKDF-Expand output) and nothing
  else in that one batch, alone, distinguishes them. **This is the claim §3
  actually supports, and it is real and measured** —
  `within_batch_real_address_is_not_identifiable_above_chance` in the test
  file.
- **Across two batches, over time, from a message that hasn't been claimed
  yet:** the real address for a still-pending index doesn't change between
  polls — [`crate::dead_drop::TagKey::address_for`] is deterministic, and
  [`MeshTransport::receive`]'s window only advances past *claimed* indices
  (design note §2, `ReceiveState`). So a real address that's still waiting
  to be delivered is queried **identically** on every subsequent poll until
  it arrives. Decoys are *added alongside* that value each time — they
  don't transform, blind, or replace it — so a carrier comparing two batches
  for a shared element finds the recurring real address exactly as easily
  with decoys present as without them. **Decoys provide zero mitigation for
  this specific attack.** `cross_poll_recurrence_of_a_pending_address_is_not_hidden_by_decoys`
  in the test file measures this directly: an adversary that flags any pair
  of batches sharing ≥1 address as "same conversation" achieves the same
  (very high) accuracy whether `k = 1` or `k` is large, because the signal
  it's using was never obscured by decoys in the first place.

**Why this doesn't fully undo §2's design, but does genuinely limit it:**
the recurrence only exposes *that the same pending interest was queried
twice* — not who is asking (radio-layer identity still rotates per Sub-Phase
4A) and not the message content. But it does mean an adversary who can
observe queries across two otherwise radio-layer-unlinkable encounters
(exactly the case 4A's token rotation exists to protect) can re-link them
at the *application* layer whenever a message is slow to arrive, partially
undermining that rotation for the specific pair of sessions involved. This
is a real, scoped gap, not eliminated by this sub-phase, and it is recorded
here — and in `docs/THREAT_MODEL.md` §3.7 — rather than left for a reader to
assume decoys cover more than they do. No fix is implemented this phase:
the honest options are (a) full PIR (already rejected in §3 as
disproportionate machinery), or (b) accepting bounded exposure scoped to
"how long a message takes to be claimed," which is the status quo. A
future mitigation worth naming, not attempted: capping how many times a
still-pending address may be re-polled before the sender is asked to
re-address the message under a fresh, unrelated tag (trading delivery
latency for reduced recurrence) — noted as a direction, not designed here.

## 6. What this does not solve, stated plainly

- **A carrier that colludes across every session a device ever polls
  through — not just one logging session — can, in principle, build a
  correlation graph decoys alone cannot fully defeat at the tested `k`.**
  §3's measurement is against a single non-colluding logging carrier;
  scaling `k` and modeling a colluding-carrier adversary explicitly is
  future work, not claimed here.
- **The dead-drop keypair enrollment is Trust-On-First-Use, same posture
  as prekey bundles and sealed-sender certificates.** No new trust
  infrastructure is introduced or claimed for it.
- **A device-seizure adversary who recovers `tag_key` recovers every past
  and future address for that conversation.** This is inherent to any
  symmetric, deterministic addressing scheme (recipient must be able to
  recompute addresses without an online lookup) and is not claimed to be
  otherwise — `tag_key` is protected only as well as the device's own key
  storage protects it, the same caveat that already applies to every other
  long-lived key this project stores.
