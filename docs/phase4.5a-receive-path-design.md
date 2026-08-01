# Phase 4.5 / Sub-Phase 4.5A — Design Note: Mix-Routed Receive Path

**Status:** Design reviewed prior to implementation | **Date:** 2026-08-01

This note exists for the same reason `docs/phase3-3a-self-destruct-design.md` and
`docs/phase4-4c-dead-drop-addressing-design.md` exist: the brief requires a
design note before code for this sub-phase, and this is the highest-priority,
highest-consequence decision in Phase 4.5 — it corrects a claim
(`docs/THREAT_MODEL.md` §3.1/§3.6 already documents the gap precisely: "Fetching
messages (`MixTransport::receive`) still talks to the relay directly, exactly
like `DirectTransport`") that currently makes the project's own headline
promise false for half of every conversation.

---

## 1. Why not a synchronous round-trip through the mix chain

The obvious-looking design — route the fetch request through the mix network
and have the response flow back the same way — was checked against the
**actual, already-implemented** mix-forwarding mechanism before being
accepted or rejected, not assumed to work by analogy with send.

Reading `mixnode/src/routes.rs::receive_packet` and
`mixnode/src/mixing.rs::schedule`/`forward`: every hop's `POST /mix/packet`
returns `202 Accepted` **immediately**, and the actual forward (or delivery)
happens in a `tokio::spawn`-detached task after that hop's independently
sampled delay. This is deliberate — module docs on `mixing::schedule` say
plainly: *"the HTTP handler that received the packet must not block its
response on another node's or the relay's latency."* There is no code path
today by which a response payload flows back through N independently-delayed
hops to the original caller.

Making that work would mean either (a) holding the client's original HTTP
connection open across the full cumulative multi-hop delay (seconds, by
design — `AVG_HOP_DELAY_MS` exists specifically to be non-trivial), which is a
real architectural change to every hop's request lifecycle, not a small one;
or (b) implementing Sphinx Single-Use Reply Blocks (SURBs), which the
original Sphinx paper (Danezis & Goldberg, IEEE S&P 2009, already cited in
`docs/THREAT_MODEL.md` §6 as the format Sub-Phase 2B implements) does specify,
but which would first require confirming the `sphinx-packet` crate this
project already depends on actually exposes SURB construction/processing —
unverified, and even if it does, the client would still need to be
**reachable** to receive the SURB-wrapped response, which a transient CLI/
mobile process generally isn't (no listening endpoint).

**Decision: neither.** Both are rejected in favor of a design that reuses the
existing fire-and-forget infrastructure completely unchanged.

---

## 2. The mechanism: a rendezvous-token indirection, not a SURB

Two decoupled legs, connected only by a client-generated, single-use random
token:

**Leg 1 — pull request (mix-routed, fire-and-forget, structurally identical
to a send):**

```
client → Sphinx-wrap { recipient_id, rendezvous_token } → mix network → final hop
```

The payload is tiny (a recipient ID and a fresh random token) and travels
exactly the way an outgoing envelope already does — same `MixTopology::choose_path`,
same `build_packet`, same per-hop delay sampling, same
`mixnet::process_packet`/`UnwrapOutcome` dispatch at each hop. The only new
thing is a destination tag, `PULL_DESTINATION_TAG`, sibling to the existing
`RELAY_DESTINATION_TAG` and `COVER_DESTINATION_TAG` — an unrecognized tag is
still refused, not guessed at, per the existing discipline. The final hop,
recognizing this tag, POSTs the decoded `{recipient_id, rendezvous_token}` to
a new relay endpoint, `POST /v1/pulls`, instead of delivering an envelope.

**Leg 2 — retrieval (direct HTTP, but carrying no identity):**

The relay, on receiving a pull request, reads (and clears) `recipient_id`'s
current message queue — the exact same operation `GET /v1/messages/{id}`
already performs — and stages the result under `rendezvous_token` in a new,
short-lived side table (not the persistent queue; a pull that's never
retrieved expires off a TTL sweep, the same shape `mesh::relay::MeshRelayAgent::sweep_expired`
already uses for a different purpose). The client, after a short randomized
delay, does `GET /v1/pulls/{rendezvous_token}` and receives whatever was
staged.

## 3. What this proves, precisely, and what it doesn't

**Proven, and tested the same way send already is:** a GPA watching the
relay's edge can no longer read `recipient_id` off the wire for the request
that actually triggers a fetch — today's `GET /v1/messages/{plaintext_id}`
disappears entirely. The pull-request leg gets exactly the send path's
existing entry/exit timing-decorrelation guarantee, verified by adapting the
identical permutation-test methodology
(`mixnode/tests/timing_correlation_tests.rs`) to pull-request entry vs.
`/v1/pulls` arrival timing.

**Not proven, stated directly rather than left to be discovered later:** the
retrieval leg (`GET /v1/pulls/{token}`) is a direct connection from the
client's real network location. It reveals no identity (the token is
unlinkable, freshly random, and carries no derivable relationship to
`recipient_id` — the relay is the only party that ever holds both halves of
the mapping, and only for the TTL window), but it does reveal the client's
IP to the relay at that moment. This is the **same class** of residual gap
already accepted and documented twice elsewhere in this project — sealed
sender "hides identity, not IP address" (§3.5), and mix-routed send: "the
client's own connection to the first mix hop is still a TCP connection a GPA
can see the source IP of" (§3.1) — not a new or worse gap introduced by this
design, but not full Loopix-style unlinkability either (that needs SURBs or
an always-reachable client, neither of which fits this architecture without
substantially larger changes than this sub-phase's mandate). Documented in
`docs/THREAT_MODEL.md` §3.1/§3.6, not implied away.

## 4. Cover pulls

`mixnode/src/cover_traffic.rs` already emits Loopix-style dummy Sphinx
packets tagged `COVER_DESTINATION_TAG` at exponentially-distributed
intervals, discarded at their final hop, indistinguishable in size/timing
from real traffic. This sub-phase extends the same scheduler to also emit
dummy `PULL_DESTINATION_TAG` packets — no new mechanism, the existing
`sample_exponential_delay` and path-selection logic apply unchanged. This
closes the coarser "does a pull happen at all, right now" timing signal at
the mix-network layer, complementing (not replacing) the per-flow timing
proof in §3.

## 5. Relay staging store: trust posture

The new `/v1/pulls` side table is held by the same `parda-relay` process,
under the same SQLCipher-backed encryption-at-rest already proven for the
message queue (`server/tests/persistence_tests.rs`). It is **not** a new
trust boundary — the relay operator already sees `recipient_id` in this
design (leg 1's final hop hands it over in the clear, exactly as the relay
already learns `recipient_id` for every send today, sealed-sender or not —
see `docs/THREAT_MODEL.md` §3.5's existing scope statement: "the relay still
needs to know where to deliver the envelope"). What changes is what an
**external observer of the wire** can read, not what the relay operator
itself already legitimately knows to do its job.

## 6. Open question resolved before implementation

Should the retrieval leg (leg 2) also be mix-routed, for full symmetry? Rejected: it would recreate exactly the "how does a response reach a
transient, non-listening client" problem §1 already rejected two solutions
for, this time for a smaller and less sensitive payload (an opaque token
lookup). The asymmetry is deliberate, bounded, and documented — not an
oversight.
