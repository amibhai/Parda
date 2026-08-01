# PARDA Threat Model

**Status:** Finalized for Phase 1 + Sub-Phase 2A + Sub-Phase 2B + Phase 3 (3A-3D) + Phase 4 (4A-4D) — v0.4.0 | Last updated: 2026-08-01

---

## 1. Overview

This document defines the threat model for PARDA (Privacy-Assured Resilient Defense Architecture). It describes the assets being protected, the assumed adversary capabilities, and the security guarantees the system aims to provide — and, just as importantly, what it does *not* yet guarantee. This is a living document; §5 tracks exactly which properties are backed by a test the reviewer can point to, versus implemented-but-unverified, versus still absent.

---

## 2. Assets

| Asset | Description |
|-------|-------------|
| Message content | The plaintext payload of any communication |
| Communication metadata | Sender identity, receiver identity, timing, frequency, message size |
| Identity keys | Long-term identity key pairs (IK) used in X3DH |
| Session keys | Ephemeral Double Ratchet keys |
| Sender certificates | Sub-Phase 2A: short-lived certificates binding an identity key to a name, used to authenticate senders inside sealed-sender envelopes |
| Device state | Local message store, key material on disk |
| Relay store contents | Sub-Phase 2A: SQLCipher database holding prekey bundles and queued envelopes |
| Mix-node identity keys | Sub-Phase 2B: X25519 keypairs mix nodes use to unwrap Sphinx onion layers. Ephemeral, in-memory only — no persistence yet (`mixnode/src/identity.rs`) |

---

## 3. Adversary Model

### 3.1 Global Passive Adversary (GPA)

The primary adversary can **observe all network traffic** on all links simultaneously — including encrypted packets, IP headers, and timing information. The GPA cannot break well-implemented cryptography but can perform traffic analysis.

**PARDA goal:** Sender-receiver unlinkability under GPA observation via mix-network routing and cover traffic (Sub-Phase 2B — **implemented for the send path**; see §3.6).

**What Sub-Phase 2B changes:** `MixTransport` (`protocol/src/transport.rs`, `protocol/src/mixnet.rs`) routes every outgoing envelope through a ≥3-hop Sphinx mix network (`parda-mixnode`) before it ever reaches `parda-relay`. A GPA watching the wire now sees, per hop, only a fixed-size Sphinx packet indistinguishable from any other real or cover packet — not the original sender's connection to the relay. `mixnode/tests/timing_correlation_tests.rs::test_send_to_arrival_timing_does_not_leak_flow_pairing_above_chance` demonstrates (via a permutation test, not eyeballing) that send-order and relay-arrival-order are not correlated above chance at the tested scale.

**What is still a gap, precisely stated (not glossed over):**
- **Receive path is unchanged.** `MixTransport::receive` fetches from the relay exactly like `DirectTransport` — a GPA watching a client's connection to the relay still sees *that a fetch happened* and to which `recipient_id`, same as Phase 1/Sub-Phase 2A. Anonymizing the pull side needs a Loopix-style provider/pull protocol, not attempted here — see `protocol/src/transport.rs` module docs.
- **No decentralized mix-node directory.** `MixTopology` is a static, trust-on-first-use configured list (same posture Phase 1/2A already accept for prekey bundles and sealed-sender certificates) — see §3.6 and §4.
- **The client's own connection to the first mix hop is still a TCP connection a GPA can see the source IP of.** Sphinx hides *content and downstream routing*, not the fact that this client is talking to *a* mix node at some observed time — cover traffic (§3.6) mitigates but does not eliminate this at low real-traffic volumes, matching Loopix's own stated limits.
- A GPA who can also compromise or subpoena the relay still learns exactly what the relay's own logs contain for the *final* hop that delivered to it (which, per §3.5, is never the true original sender for a sealed-sender + mix-routed message) — nothing more, nothing less.

### 3.2 Active Relay-Node Adversary (Sub-Phase 2B mix network)

An adversary who **controls one or more mix nodes** in a Sub-Phase 2B routing path. Such an adversary may drop, delay, or replay packets but cannot learn the full routing path of any single Sphinx packet through an honest node.

**PARDA goal:** No single compromised mix node breaks anonymity; requires **all N nodes** in a message's path to collude to fully de-anonymize that message (see §3.6 for the precise per-hop guarantee — this is *not* the same as "N-1 colluding nodes," which overstates what a Sphinx/Loopix-style design actually provides).

**Status:** Implemented — Sub-Phase 2B. Each hop unwraps exactly one Sphinx onion layer (`parda_protocol::mixnet::process_packet`, built on the `sphinx-packet` crate — Danezis & Goldberg, IEEE S&P 2009) and cannot recover the sender, the full path, or the destination beyond its own immediate next hop. A malicious or merely broken node can drop or delay a packet — `mixnode/tests/degradation_tests.rs::test_dropped_packet_degrades_to_never_arrives_not_misdelivery` and `::test_delayed_hop_still_delivers_correct_plaintext_eventually` demonstrate the system degrades to "message lost" or "message late," never to a misdelivery or a signal back to the sender about which hop misbehaved.

### 3.3 Server-Side Compromise (relay or CA)

An adversary who **fully compromises `parda-relay`** — its process memory, its SQLCipher database (with the key), and the sealed-sender certificate authority it hosts (§3.5).

**What this adversary still cannot do:**
- Decrypt past message content (Double Ratchet forward secrecy — §3.3.1, tested).
- Decrypt sealed-sender envelopes' inner content or recover the sender identity of a *past* message beyond what was ever visible to the relay (which, per §3.5, is nothing for `sealed_sender = true` envelopes).
- Forge a valid `SenderCertificate` for the *trust root* — only for certificates chained under the CA it runs. If the relay's CA is compromised, the adversary can mint certificates claiming any `sender_uuid` for any identity key it chooses; every client that trusts that relay's trust root would accept such a forged certificate as authentic. **This is the load-bearing trust assumption of Sub-Phase 2A** — see §3.5.

#### 3.3.1 Forward secrecy (Phase 1, tested)

Per-message ephemeral Double Ratchet keys mean an adversary who compromises a session at step N cannot decrypt messages from steps 0…N-1. Proven by `protocol/tests/crypto_tests.rs::test_forward_secrecy_stale_ciphertext_rejected`.

### 3.4 Device Seizure Adversary

An adversary with **physical access to a device** after message delivery. May attempt forensic recovery of message content from storage, swap space, or memory.

**PARDA goal:** Cryptographic self-destruct eliminates key material post-expiry; secure memory wiping prevents recovery from volatile storage.

**Status: Phase 3 complete through Sub-Phase 3D** (time-bound expiry, read-triggered destruction, live-memory zeroization, swap-avoidance for the derived key, forensic-recovery capstone test, session-burn, encrypted client-side history store, REST gateway, and a real CLI exercising all of it end-to-end). `parda_protocol::self_destruct::SelfDestructingMessage` derives a fresh, local key (HKDF-SHA256, `docs/phase3-3a-self-destruct-design.md`), re-encrypts the recovered plaintext under it (ChaCha20-Poly1305), locks its backing memory (`secure_memory`, `mlock`/`VirtualLock`) for as long as it's alive, and erases that key — provably, per
`protocol/src/self_destruct.rs`'s memory-forensics tests — either when a monotonic-clock-anchored timer expires (`seal`, time-bound) or atomically on first successful read (`seal_read_triggered`, read-triggered — erasure happens inside the same held lock as the decrypt, before returning to the caller, so there is no window in which a second reader could find the key still live; see design note §5b). **This is a genuinely narrower claim than the PARDA goal above states**, and the gap is specific:

- **What's proven:** the derived key is gone from *live, resident* process memory after expiry/read — not merely unreachable through the API. Proven for the erasure mechanism itself two ways: reading the same live-typed reference immediately before/after the explicit zeroize call (`test_erase_zeroizes_before_clearing_and_ends_up_gone`), and, on Linux, scanning all of `/proc/self/mem` for the key's exact bytes before and after (`test_key_bytes_absent_from_process_memory_after_expiry`). Read-triggered atomicity — no double-read, even under a race — is proven by `test_read_triggered_concurrent_opens_only_one_succeeds`: 32 callers released simultaneously via a barrier all race to open the same message; exactly one succeeds, every run, deterministically (a mutex-structural guarantee, not a timing-dependent one). The derived key's memory is locked from creation to erasure, verified against the OS's own accounting (`/proc/self/status`'s `VmLck`, Linux) rather than trusting `mlock`'s return code alone, and shown to survive 256 MiB of unrelated memory pressure without the lock being silently dropped. The forensic-recovery capstone test (`protocol/tests/forensic_recovery_tests.rs`) simulates seizure immediately after destruction fires for both modes and confirms the plaintext is unrecoverable — the sub-phase's actual deliverable, per the brief's own framing.
- **What's explicitly NOT yet proven or defended:** hibernation (which can snapshot locked pages to disk by design — `mlock` does not defend against this); the plaintext buffer `open()` returns is zeroized but not memory-locked (only the derived key is — see design note §8); Windows lacks a low-friction way to verify locking via OS accounting the way Linux's `VmLck` does, so verification there is limited to `VirtualLock`'s return code; and — critically for *this* adversary specifically — **an adversary who obtains a memory dump *before* expiry/read fires always gets the plaintext.** No cryptographic self-destruct scheme changes that; PARDA does not claim otherwise. **A self-destructing message still does not survive an app restart while still pending** — `parda-client-store` (Sub-Phase 3D) persists message history, but its write path structurally *refuses* any envelope with `self_destruct_at` set or `read_triggered_destruct = true` (`LocalMessageStore::store_message`, tested); this is correct, deliberate behavior for the persistence/destructibility boundary, not a bug, but it does mean a self-destructing message that arrives while the app is closed and isn't opened before the app is later killed has no restart-surviving holding area at all yet.
- **Clock trust (this adversary's core capability, time-bound mode only):** since this adversary has the device, they can change its wall clock. Primary defense is a monotonic (`Instant`) timer, immune to wall-clock changes for as long as the process runs; `clock_guard`'s persisted watermark detects and fails closed on a wall-clock rollback across a process restart. **Neither defends against a rooted/jailbroken device that can also rewrite the persisted watermark file directly, nor against a device that's powered off and never allowed to run the app process again** — both are stated plainly as unsolved in `docs/phase3-3a-self-destruct-design.md` §3, not glossed over. Read-triggered mode has no clock dependency at all — its own gap is different: a message that's never read stays readable indefinitely, which is its documented contract, not a flaw.
- **Session-level destruct ("burn this conversation," Sub-Phase 3D) has a materially weaker guarantee than message-level self-destruct, by necessity, not oversight.** `SessionManager::burn_conversation` removes session and trust state from PARDA's own store — real, tested (`protocol/tests/session_burn_tests.rs`) — but cannot provably zeroize the underlying key bytes: `libsignal-protocol` v0.66.0's `PrivateKey` is a non-zeroizing `Copy` type (confirmed by reading `rust/core/src/curve.rs` in the pinned tag), so libsignal's own internals may hold implicit copies no code in this project can see or overwrite without forking libsignal. See design note §12.
- **Mobile client, audited (§9 of the design note):** no self-destruct integration exists on mobile yet — Sub-Phase 3D built the CLI/store/gateway application layer, not the mobile one. Auditing the *existing* Phase 1 plaintext handling in `SignalPlugin.kt` found decrypted plaintext crossing the MethodChannel boundary in a JVM `ByteArray` with no explicit clearing; fixed by zeroizing it after use — **this fix is reasoned-correct but still not runtime-verified against a real Flutter/Android build** (a different toolchain gap than the Perl one Sub-Phase 3D resolved for the Rust crates; not attempted). A deeper, unresolved finding: `session_service.dart` converts plaintext to a Dart `String`, which has no mutable backing storage — **the current mobile architecture cannot provide a "provably erased" guarantee once plaintext becomes a `String`, independent of any zeroize discipline applied earlier in the chain.** No iOS native bridge exists at all to audit.

### 3.5 Curious/Malicious Relay Operator (Sub-Phase 2A — implemented and tested)

An adversary who runs, or has subpoenaed/compromised, the relay process and can read **everything it stores, logs, and returns over HTTP** — but does not control the network path (see §3.1 for that) and has not compromised any client device.

**Precise guarantee:** For any envelope sent with `sealed_sender = true`, this adversary cannot recover the sender's identity from:
- the relay's persistent store (SQLCipher database — `sender_id` is stored as `""`),
- the relay's log output (every log line in `routes.rs` is written to never reference `envelope.sender_id`),
- the relay's HTTP responses (submit/fetch responses never echo a sender field).

The adversary *can* still see: `recipient_id` (routing requires it), envelope size and arrival timing, and — critically — **the source IP address of whichever connection POSTed the message**, since sealed sender is an application-layer property and PARDA has no TLS termination or IP-hiding transport in front of the relay yet (Phase 1 Known Risk #3, still open). Sealed sender is not an IP-anonymity mechanism; it is what Sub-Phase 2B's mix routing is for.

**Tested by:**
- `protocol/tests/sealed_sender_tests.rs` — cryptographic properties: round-trip authentication, rejection of wrong trust root / expired / forged certificates, and that `decrypt()` (non-sealed path) refuses to touch a sealed envelope.
- `server/tests/sealed_sender_relay_tests.rs::test_malicious_relay_cannot_recover_sender_identity` — a harness with full access to the real relay's captured logs and live store contents, run across a corpus of N=12 distinct sealed senders, asserting none is recoverable.

**Trust assumption this does NOT eliminate:** the relay's sealed-sender CA has no account authentication behind it (`/v1/certs/{user_id}` issues a certificate for whatever identity key is presented — the same Trust-On-First-Use posture Phase 1 already had for `/v1/keys/{user_id}` prekey bundle uploads). A network-level MITM or a malicious relay operator *at enrollment time* could issue itself a certificate claiming to be someone else's `sender_uuid` bound to an attacker-controlled identity key, and any recipient who later X3DH-handshakes with that attacker (believing it to be the real user) would accept sealed messages "from" that forged identity. This is bounded, not eliminated, by the same out-of-band safety-number verification Phase 1 already recommends for identity key trust (`docs/phase1-architecture.md` §10, risk #3) — sealed sender authenticates *within* an established trust relationship, it does not establish one.

### 3.6 Sub-Phase 2B Mix-Network Adversary Capability Boundaries (implemented)

This section states what Sphinx packet path-length, per-hop delay, and cover-traffic parameters actually deliver, as answers to threat-model questions rather than free variables picked for implementation convenience — read before changing any of `mixnet::MIN_PATH_LENGTH`, `MixTransport::DEFAULT_AVG_DELAY`, or `MIXNODE_COVER_AVG_INTERVAL_MS`.

**Compromise threshold:** For a message routed over a path of length N (N ≥ 3, enforced by `mixnet::MIN_PATH_LENGTH` — `build_packet`/`build_packet_to` refuse a shorter path), sender-receiver unlinkability for that message holds as long as **at least one node on its path is honest**. This is the standard Sphinx/Loopix per-message guarantee: each honest hop re-randomizes the packet's cryptographic appearance and (with cover traffic + per-hop delay) its timing correlation, so a single honest hop is sufficient to break the adversary's ability to link the packet's pre-hop and post-hop appearance. Equivalently: **all N nodes on a given message's path must collude** to fully deanonymize that specific message. (Note this is *per-message*: an adversary controlling most-but-not-all nodes network-wide still cannot deanonymize any message that happens to route through the one honest node it doesn't control — but with high compromise fractions, the *probability* that a random path avoids the honest set drops accordingly. That probability, not a fixed node count, is the real security parameter, and `MixTopology::choose_path`'s uniform-random selection over the configured topology is what that probability is computed against for any real deployment — PARDA does not compute or enforce a minimum honest-node fraction operationally; that's a deployment-time decision, not a code-level guarantee.)

**Mixing mechanism, precisely:** per-hop delay is sampled by the *sender* from an exponential distribution (`sphinx_packet::header::delays::generate_from_average_duration`, mean configurable, default 200ms — Piotrowska et al., "The Loopix Anonymity System," USENIX Security 2017) and embedded in the Sphinx header; each node honors the delay it's handed rather than sampling its own (`protocol/src/mixnet.rs` module docs explain why: a node that samples its own delay could be influenced or fingerprinted by comparing its behavior to the sender-committed distribution). This is continuous-time mixing, not batch-and-flush — see `mixnode/src/mixing.rs` module docs for why that distinction matters (batching would reintroduce a "which packets shared a batch" correlation signal).

**Cover traffic:** each mix node independently emits Loopix-style "drop cover" packets (`mixnode/src/cover_traffic.rs`) at exponentially-distributed intervals, routed through a real ≥3-hop path of its configured peers and discarded at the final hop rather than delivered. This requires `MIXNODE_PEERS` to be configured with at least `mixnet::MIN_PATH_LENGTH` peers — **a node with fewer configured peers emits no cover traffic at all** (logged as a warning, not silently degraded to "less cover traffic"). This is a real, documented operational gap: an under-configured node's real-traffic volume alone is observable to a GPA at that node's edges.

**What a Global Passive Adversary (§3.1) still learns even under full protocol correctness:**
- Aggregate traffic volume in and out of the mix network as a whole.
- That *some* client is active, from connection timing to its entry node (cover traffic reduces but does not perfectly eliminate this at low traffic volumes, and not at all for nodes with `MIXNODE_PEERS` unconfigured — this is a Loopix-inherited limitation, not a PARDA-specific one).
- Anything visible at a node the GPA also controls (composing with §3.2).
- The `recipient_id` of the *fetch* request against the relay (§3.1 receive-path gap).

**What a GPA does NOT get, as long as ≥1 honest hop exists on the path, at the tested scale:**
- A confirmed sender→receiver *entry/exit timing* pairing for a specific message, above the false-positive rate `mixnode/tests/timing_correlation_tests.rs` demonstrates via a permutation test (Spearman rank correlation between send-order and relay-arrival-order for the true pairing, tested against random re-pairings). This is an **empirical result bounded to the tested parameters** (10 flows, 3-hop paths, mean 150ms/hop delay in the checked-in test) — not a formal, asymptotic anonymity proof, and not automatically true at arbitrarily different traffic volumes, path lengths, or delay settings. Re-verify this test (or a scaled variant of it) before trusting a materially different production configuration.

**Explicitly out of scope, still:** full mix-network compromise (§4) — if every node is adversary-controlled, PARDA makes no anonymity claim, matching Loopix's own stated limits. Also out of scope: any adversary who obtains a live memory/packet capture of an honest mix node itself (distinct from network observation — see the physical-adversary considerations that Phase 3 will formalize for device seizure).

### 3.7 Co-located Radio Adversary (Phase 4, implemented)

An adversary **physically present in BLE/Wi-Fi range** during an active mesh
session — a passive scanner logging every advertisement and connection it
observes, or an active participant who joins the mesh as a store-and-forward
carrier (§3.7.1 below). This is a materially different adversary from every
one above: §3.1-§3.6 assume the adversary observes a network link or
compromises a host; this one observes **radio spectrum directly**, which no
software running on PARDA's endpoints can hide the existence of. Stated
plainly, once, rather than qualified away in each subsection below: **a
broadcast radio is a broadcast radio — no key management scheme changes RF
physics, and PARDA does not claim otherwise.**

**What is defended, precisely:**
- **No persistent radio-layer identifier.** `parda_mesh::radio::AdvertToken`
  is fresh `OsRng` bytes plus a fixed, public 2-byte protocol tag — nothing
  else is ever advertised (no device name, no per-device service UUID).
  `parda_mesh::radio::RotatingIdentity` draws a new token every
  `DEFAULT_ROTATION_INTERVAL` (120s, a threat-model parameter, not a
  hardcoded floor). `mesh/tests/passive_scanner_tests.rs` proves, measured
  against a random-guess baseline (not just asserted zero): no two
  advertisements from the same simulated device across different rotation
  windows are bit-identical (`full_token_adversary_finds_zero_cross_window_links_at_128_bits`),
  and even a drastically weakened partial-byte signal doesn't beat chance
  (`one_byte_prefix_adversary_does_not_beat_random_guess_baseline_by_more_than_margin`).
- **Store-and-forward carrier opacity.** `parda_mesh::relay::MeshRelayAgent`
  indexes bundles by a blinded address only (§3.7.2) and never decodes a
  bundle's payload block into a `MessageEnvelope`. `mesh/tests/malicious_carrier_tests.rs::malicious_carrier_cannot_recover_any_known_marker_from_raw_storage`
  gives a simulated adversary **direct access to its own raw backing store**
  (not the relay's own query API — a real attacker with the device wouldn't
  be limited to it either) holding a corpus of known plaintext/identity
  markers, and proves none is recoverable.
- **Flood/Sybil resistance.** Because Sub-Phase 4A deliberately gives peers
  no stable identity across sessions (the property directly above), classic
  per-identity rate limiting doesn't apply — `mesh/src/relay.rs` module docs
  explain why the actual defense is a hard global storage cap plus a small
  per-connection-session admission cap instead, raising the cost of flooding
  without claiming to eliminate it for an attacker willing to reconnect
  repeatedly. `mesh/tests/flood_resistance_tests.rs` proves storage stays
  bounded under a direct flood, under a single oversized sync session, and
  that a flood cannot evict already-stored honest bundles.
- **Mesh partition/rejoin correctness.** `mesh/tests/partition_rejoin_tests.rs`
  proves no duplicated or dropped bundle across a partition-and-heal cycle,
  including a two-path rejoin scenario and a carrier that goes offline mid-mesh
  while still holding an in-flight bundle. `mesh/tests/multinode_simulation_tests.rs`
  runs the same underlying mechanism at N=30 nodes on a ring topology under a
  fixed churn schedule, not just two-node cases.
- **Retrieval-pattern mitigation, measured.** See §3.7.2.
- **Self-destruct still fires under mesh latency.** `mesh/tests/expiry_tests.rs`
  proves a bundle that expires before pickup is purged and never delivered,
  and that a partition delaying delivery past the deadline produces the same
  outcome (not a race that sometimes delivers anyway).

**What is NOT defended — stated directly, not implied away:**
- **Raw presence detection.** An observer with a BLE/Wi-Fi scanner in
  physical range learns *that a PARDA node is active nearby, right now* —
  this is unavoidable and inherent to using broadcast radio at all, not a
  gap specific to this implementation. Rotation defeats *re-identifying the
  same device across two separate encounters*; it does not and cannot defeat
  *detecting a device is present during one encounter*.
- **Platform MAC/link-layer address rotation is outside application
  control on every platform researched.** iOS hides the underlying address
  from apps entirely (assigns a random per-app `CBPeripheral` UUID instead)
  and rotates the real address at the OS level on its own ~15-minute
  schedule, with zero app-level control. Android's address-randomization
  behavior is OS/manufacturer policy (observed absent on some Samsung
  devices in prior research), also with no fine-grained app control.
  Linux/BlueZ's resolvable-private-address rotation is a kernel/`bluetoothd`
  privacy-subsystem setting, not something `parda_mesh::radio::bluez` drives
  per advertisement. What this project's code controls — and the only thing
  [`AdvertToken`] rotation actually claims to control — is the *advertised
  payload*, not the underlying radio link-layer address. See
  `mesh/src/radio/mod.rs` module docs and the README limitations table.
- **Real backends exist for exactly one platform.** `bluer`/BlueZ (Linux)
  is the one real, compiling backend this phase ships. CoreBluetooth
  (macOS/iOS), Android, and Windows are documented, cited gaps — trait-ready,
  not implemented — not stub code that pretends to work. No GitHub-hosted CI
  runner has a Bluetooth radio either, so even the real backend's
  `advertise`/`scan`/`connect`/`accept` are never exercised against actual RF
  in CI — see `mesh/src/radio/bluez.rs` module docs.
- **No real Wi-Fi Direct platform binding.** No viable Rust crate for Wi-Fi
  Direct was found for any target platform (checked, not assumed) — the
  large-bundle-transfer path is proven at the protocol level via
  `SimulatedMeshRadio`'s `SimProfile::WifiDirect` profile only.
- **Cross-poll recurrence of a still-pending address is not hidden by
  decoy queries** — a genuine, measured limitation, not a qualitative
  aside. See §3.7.2.

#### 3.7.1 Malicious/Sybil relay-agent adversary (implemented, bounded not eliminated)

An adversary running one or more `parda_mesh::relay::MeshRelayAgent`
instances (or one physical radio presenting many rotating identities) that
floods garbage bundles or attempts to exhaust an honest carrier's storage.
Same evidence as the flood/Sybil bullet above.
**Explicitly not eliminated:** an attacker willing to physically reconnect
repeatedly can still consume the global cap over enough sessions — the
per-session admission cap raises the real-world (time/energy) cost of doing
so, it does not make it impossible, because this project deliberately does
not build the persistent-identity infrastructure that would be needed to
rate-limit by identity instead (that infrastructure would itself be a
tracking capability, which Sub-Phase 4A exists specifically to avoid).

#### 3.7.2 Dead-drop addressing and retrieval-pattern adversary (implemented, scoped)

Covers `parda_protocol::dead_drop` (the blinded addressing construction) and
the decoy-query retrieval-pattern mitigation — both designed in
`docs/phase4-4c-dead-drop-addressing-design.md`, reviewed before
implementation per this phase's own required process.

**Address blinding:** a bundle's storage address
(`dead_drop::TagKey::address_for`) is an HKDF-SHA256 output derived from a
dedicated, purpose-only X25519 keypair per conversation (never the Signal
identity key, never reachable from inside the Double Ratchet session — see
design note §1) and a monotonic per-peer counter (not wall-clock time, to
avoid re-importing Phase 3's clock-trust gaps — design note §2). A carrier
observing the address alone learns nothing about recipient identity;
`mesh/tests/malicious_carrier_tests.rs::destination_address_reveals_nothing_without_the_key`
and `retrieval_pattern_tests.rs::distinct_indices_do_not_spuriously_share_addresses`
cover this directly.

**Retrieval-pattern mitigation — measured, with an honest boundary on what
it covers:**
- **What decoy queries prove, measured:** given a *single* poll batch in
  isolation, an adversary cannot identify the real address among `k-1`
  fresh random decoys with better than `1/k` accuracy —
  `mesh/tests/retrieval_pattern_tests.rs::within_batch_real_address_is_not_identifiable_above_chance`,
  measured across 2000 trials per `k` against the random-guess baseline, not
  asserted from first principles alone.
- **What decoy queries do NOT prove, found while building that
  measurement, not assumed:** a still-pending (not yet claimed) message's
  real address is deterministic and unchanged across repeated polls: decoys
  are added *alongside* it each time, not used to transform or hide it, so
  an adversary comparing two poll batches for a shared element recovers the
  recurrence with the same (very high) accuracy whether decoys are present
  or not.
  `retrieval_pattern_tests.rs::cross_poll_recurrence_of_a_pending_address_is_not_hidden_by_decoys`
  measures this directly and asserts the before/after accuracy are within
  2% of each other — i.e., decoys measurably do nothing for this specific
  attack. See design note §3a for the full account. **Practical
  consequence:** an adversary who can observe queries across two otherwise
  radio-layer-unlinkable encounters (exactly what Sub-Phase 4A's token
  rotation exists to prevent) can re-link those two encounters at the
  *application* layer whenever a message is slow enough to still be pending
  on both polls — content and recipient identity remain protected, but the
  *fact that the same interest recurred* does not. Not fixed this phase;
  full PIR was considered and rejected as disproportionate machinery for a
  single-hop intermittent mesh carrier model (design note §3).

---

## 4. Out of Scope (Current Phase)

- **Quantum adversaries:** Post-quantum key encapsulation (ML-KEM) and signatures (ML-DSA) are planned for a future phase. The current design uses X25519 and Ed25519. (`libsignal-protocol`'s Kyber prekey storage trait is implemented as an unused stub — see `protocol/src/store.rs` — solely because the pinned library version requires it structurally; no PQXDH handshake is performed.)
- **Full mix-network compromise:** PARDA does not claim anonymity if all nodes in a routing path are colluding (§3.6).
- **IP-address anonymity for the client's connection to its first mix hop:** Sub-Phase 2B hides which mix node ultimately delivers to the relay, and hides content/routing from intermediate hops, but a GPA watching a specific client's network link still sees that client talking to *some* mix node. No Tor-style guard rotation or additional transport-layer anonymization is implemented.
- **Receive-path (message fetch) anonymization:** unchanged from Phase 1/Sub-Phase 2A — see §3.1 and §3.6.
- **Decentralized mix-node directory / topology authority:** `MixTopology` is static and trust-on-first-use, same posture as prekey bundle upload and sealed-sender certificate issuance (§3.5). No freshness, revocation, or Byzantine-fault-tolerant directory consensus exists.
- **Endpoint compromise prior to message creation:** If the sending device is compromised before message composition, no protocol-level protection applies.
- **Sealed-sender CA enrollment authentication:** see §3.5's trust-assumption paragraph.
- **Acoustic / physical side-channel attacks**
- **Denial-of-service resilience:** a mix node that receives a flood of malformed or excessive-volume packets has no rate limiting; a Sphinx-unwrap failure is rejected per-packet (fail closed) but nothing yet throttles an adversary who simply sends many packets.
- **Raw radio-layer presence detection (Phase 4):** no software fix changes RF physics — see §3.7.
- **Real CoreBluetooth (macOS/iOS), Android, and Windows mesh backends:** trait-ready (`parda_mesh::radio::MeshRadio`), not implemented this phase — see §3.7 and the README limitations table for the specific, cited restriction per platform.
- **Real Wi-Fi Direct platform binding:** no viable Rust crate found for any target platform (checked, not assumed) — see §3.7.
- **Full PIR/hidden-access-pattern retrieval:** considered (Talek, Cheng et al. ACSAC 2020) and rejected as disproportionate machinery for a single-hop intermittent mesh carrier model — see §3.7.2 and design note §3. Decoy queries are a narrower, measured mitigation, not a PIR-equivalent guarantee.
- **Colluding-carrier retrieval-pattern correlation:** §3.7.2's measurement is against a single non-colluding logging carrier; a carrier that colludes with every other carrier a device ever polls through is a strictly stronger adversary not defeated by this phase's mitigation.
- **Mesh flood/Sybil resistance against an attacker willing to reconnect indefinitely:** raised in cost, not eliminated — see §3.7.1. Building persistent-peer-identity infrastructure to rate-limit by identity was deliberately not done, since that infrastructure would itself be the tracking capability Sub-Phase 4A exists to avoid.
- **Mobile (Flutter/Dart/Kotlin/Swift) mesh integration:** out of scope this phase, consistent with Phase 3's self-destruct mobile-UI deferral — no mesh-mode UI or native bridge exists yet.
- **On-device power/battery measurement:** `mesh/tests/battery_cost_tests.rs` measures operation counts and wire-byte sizes at this crate's actual parameters, not real milliwatt draw — no BLE hardware exists in the environment this phase was built in to measure that. See README limitations.

---

## 5. Security Properties Claimed

Every ✅ row below is backed by a named test a reviewer can run; nothing is marked done on the strength of the implementation alone.

| Property | Status | Evidence |
|----------|--------|----------|
| Message confidentiality (E2EE) | ✅ Implemented & tested — Phase 1 | `protocol/tests/crypto_tests.rs::test_double_ratchet_encrypt_decrypt_roundtrip` |
| Forward secrecy | ✅ Implemented & tested — Phase 1 | `protocol/tests/crypto_tests.rs::test_forward_secrecy_stale_ciphertext_rejected` |
| Break-in recovery | ✅ Implemented — Phase 1 (Double Ratchet self-healing is inherent to the libsignal session state machine used) | Not separately adversarially tested; relies on upstream libsignal-protocol correctness |
| Sender-receiver unlinkability **from the relay operator** | ✅ Implemented & tested — Sub-Phase 2A | `server/tests/sealed_sender_relay_tests.rs`, `protocol/tests/sealed_sender_tests.rs` |
| Sender-receiver unlinkability **under network-level GPA / traffic timing analysis (send path)** | ✅ Implemented & tested — Sub-Phase 2B | `mixnode/tests/timing_correlation_tests.rs::test_send_to_arrival_timing_does_not_leak_flow_pairing_above_chance` (empirical, scale-bounded — see §3.6) |
| Mix routing degrades to loss/delay, not deanonymization, when a hop misbehaves | ✅ Implemented & tested — Sub-Phase 2B | `mixnode/tests/degradation_tests.rs::test_dropped_packet_degrades_to_never_arrives_not_misdelivery`, `::test_delayed_hop_still_delivers_correct_plaintext_eventually` |
| Mix transport fails closed (no metadata-leaking fallback) when the network is unreachable | ✅ Implemented & tested — Sub-Phase 2B | `protocol/tests/mixnet_tests.rs::test_mix_transport_send_fails_closed_when_first_hop_unreachable` |
| Envelope wire-format version mismatch fails loud | ✅ Implemented & tested | `protocol/tests/crypto_tests.rs::test_envelope_future_version_rejected_explicitly`, `::test_envelope_missing_version_defaults_to_v1` |
| Relay store encrypted at rest | ✅ Implemented & tested — Sub-Phase 2A | `server/tests/persistence_tests.rs::test_database_file_is_not_plaintext_on_disk`, `::test_wrong_key_cannot_read_database` |
| Relay store survives restart | ✅ Implemented & tested — Sub-Phase 2A | `server/tests/persistence_tests.rs::test_data_survives_simulated_restart` |
| Sender-receiver unlinkability (receive/fetch path) | 🔲 Not implemented — see §3.1, §3.6, §4 | Not started |
| Time-bound self-destruct key derivation (HKDF-SHA256, local secret) | ✅ Implemented & tested — Sub-Phase 3A | `protocol/src/self_destruct.rs::tests::test_seal_open_roundtrip`, `::test_different_modes_derive_different_keys_from_the_same_seed` |
| Self-destruct key provably erased from live process memory at expiry | ✅ Implemented & tested — Sub-Phase 3A | `protocol/src/self_destruct.rs::tests::test_erase_zeroizes_before_clearing_and_ends_up_gone`, `::linux_memory_scan_tests::test_key_bytes_absent_from_process_memory_after_expiry` (Linux only) |
| Clock-rollback detection, fail-closed | ✅ Implemented & tested — Sub-Phase 3A | `protocol/src/clock_guard.rs::tests::test_rollback_is_detected_and_watermark_not_advanced`, `protocol/tests/self_destruct_tests.rs::test_clock_rollback_forces_fail_closed_and_permanently_expires_the_message` |
| Read-triggered self-destruct, no timer dependency | ✅ Implemented & tested — Sub-Phase 3B | `protocol/tests/self_destruct_tests.rs::test_read_triggered_message_has_no_timer_and_survives_until_read` |
| Read-triggered destruction is atomic (no double-read, including under a race) | ✅ Implemented & tested — Sub-Phase 3B | `protocol/tests/self_destruct_tests.rs::test_read_triggered_concurrent_opens_only_one_succeeds`, `::test_read_triggered_second_open_fails_closed_after_first_succeeds` |
| Derived key's memory locked against swap (`mlock`/`VirtualLock`), verified via OS accounting | ✅ Implemented & tested — Sub-Phase 3C | `protocol/src/secure_memory.rs::tests::test_lock_increases_os_reported_locked_byte_count` (Linux), `::test_locked_region_accounting_survives_memory_pressure` (Linux) |
| Forensic-recovery capstone test: plaintext unrecoverable after simulated seizure, both modes | ✅ Implemented & tested — Sub-Phase 3C | `protocol/tests/forensic_recovery_tests.rs` (all 4 tests; the 2 Linux-only ones do a literal `/proc/self/mem` dump) |
| Mobile native-bridge audit | ✅ Audited — Sub-Phase 3C | `docs/phase3-3a-self-destruct-design.md` §9; Kotlin fix in `SignalPlugin.kt` (not yet runtime-verified — see §11) |
| Plaintext buffer (not just the derived key) memory-locked | 🔲 Not implemented — see design note §8 | Not started |
| Session-level "burn this conversation" | ✅ Implemented & tested — Sub-Phase 3D (materially weaker guarantee than message self-destruct — see above) | `protocol/tests/session_burn_tests.rs` (4/4) |
| Client-side encrypted message history store, structurally excludes self-destructing messages | ✅ Implemented & tested — Sub-Phase 3D | `client-store/tests/client_store_tests.rs` (7/7, incl. `test_refusal_does_not_partially_write_anything`) |
| CLI prototype exercising full flow end-to-end (real HTTP transport, both destruct modes, burn) | ✅ Implemented & run — Sub-Phase 3D | `cli/src/main.rs` `demo` subcommand — run directly (not just `cargo test`) for all 3 modes plus the mutually-exclusive-flags rejection, all exiting as designed |
| REST API gateway (typed, versioned, provably never touches plaintext/keys) | ✅ Implemented & tested — Sub-Phase 3D | `gateway/tests/gateway_tests.rs` (3/3, incl. `test_ciphertext_passes_through_bit_identical`) |
| `DirectTransport`/`MixTransport::receive` correctly parses the relay's actual response shape | ✅ Fixed & tested — found via the Sub-Phase 3D CLI's first real run | `protocol/src/transport.rs` (`FetchMessagesResponse`); latent since Phase 1, no prior test exercised `receive()` against a live relay |
| Self-destructing message surviving an app restart while pending | 🔲 Not implemented — deliberately excluded from `parda-client-store`, no replacement holding area built yet | Not started |
| No persistent radio-layer advertisement identifier | ✅ Implemented & tested — Sub-Phase 4A | `mesh/tests/passive_scanner_tests.rs` (all 3 tests, measured against random-guess baseline) |
| Real BLE backend on at least one platform | ✅ Implemented — Sub-Phase 4A (Linux/`bluer` only; not compiled/run in this session — see §3.7) | `mesh/src/radio/bluez.rs`; compiled in CI's `mesh-adversarial` job, Linux leg, `--features bluez` |
| DTN store-and-forward relay agent, RFC 9171 bundle framing | ✅ Implemented & tested — Sub-Phase 4B | `mesh/src/bundle.rs`, `mesh/tests/*` (bundle round-trip, opacity) |
| Flood/Sybil resistance (bounded storage, session admission cap, TTL sweep) | ✅ Implemented & tested — Sub-Phase 4B | `mesh/tests/flood_resistance_tests.rs` (4/4) |
| Malicious carrier cannot recover plaintext/sender/recipient from its own storage | ✅ Implemented & tested — Sub-Phase 4B | `mesh/tests/malicious_carrier_tests.rs` (3/3) |
| Mesh partition/rejoin: no duplication, no silent loss | ✅ Implemented & tested — Sub-Phase 4B/4D | `mesh/tests/partition_rejoin_tests.rs` (3/3), `mesh/tests/multinode_simulation_tests.rs` (N=30 ring + churn) |
| Blinded dead-drop addressing scheme (HKDF over a dedicated X25519 shared secret) | ✅ Implemented & tested — Sub-Phase 4C | `docs/phase4-4c-dead-drop-addressing-design.md`; `protocol/src/dead_drop.rs::tests` (6/6) |
| Retrieval-pattern mitigation (decoy queries), within-batch claim | ✅ Implemented & tested — Sub-Phase 4C | `mesh/tests/retrieval_pattern_tests.rs::within_batch_real_address_is_not_identifiable_above_chance` |
| Retrieval-pattern cross-poll recurrence — explicitly NOT mitigated by decoys | 🔲 Known, measured limitation — Sub-Phase 4C, see §3.7.2 | `mesh/tests/retrieval_pattern_tests.rs::cross_poll_recurrence_of_a_pending_address_is_not_hidden_by_decoys` |
| Dead-drop address wired into `MessageEnvelope`, transport-agnostic (one envelope, any transport) | ✅ Implemented & tested — Sub-Phase 4C | `protocol/src/envelope.rs::dead_drop_address`; `mesh/tests/transport_tests.rs` (4/4) |
| Self-destruct expiry correct under mesh latency, including expire-before-pickup | ✅ Implemented & tested — Sub-Phase 4C | `mesh/tests/expiry_tests.rs` (4/4) |
| Hybrid online/mesh handoff, no message loss/duplication across the transition | ✅ Implemented & tested — Sub-Phase 4D | `mesh/tests/hybrid_handoff_tests.rs` (2/2) |
| Combined field scenario: real `MixTransport` + `MeshTransport` under `HybridTransport`, mixed with mesh-only messages | ✅ Implemented & tested — Sub-Phase 4D | `mesh/tests/combined_field_scenario_tests.rs` (2/2) |
| Battery/resource cost characterized (operation counts, wire bytes) | ✅ Measured — Sub-Phase 4D (operation counts only, no on-device power draw — see §3.7 and README) | `mesh/tests/battery_cost_tests.rs` (3/3) |
| Real CoreBluetooth (macOS/iOS), Android, Windows mesh backends | 🔲 Not implemented — documented gap, not stub code — see §3.7 | Not attempted, no toolchain in this environment |
| Real Wi-Fi Direct platform binding | 🔲 Not implemented — no viable Rust crate found for any platform | Not attempted |
| Mobile (Flutter/Dart/Kotlin/Swift) mesh integration | 🔲 Out of scope this phase, same precedent as Phase 3's self-destruct mobile-UI deferral | Not attempted |
| Post-quantum resistance | 🔲 Future (not in scope v0.x) | Not started |

---

## 6. References

- Cohn-Gordon et al., "A Formal Security Analysis of the Signal Messaging Protocol" (IEEE EuroS&P 2017)
- Danezis & Goldberg, "Sphinx: A Compact and Provably Secure Mix Format" (IEEE S&P 2009) — the packet format Sub-Phase 2B implements via the `sphinx-packet` crate (Nym Technologies, Apache-2.0, crates.io, github.com/nymtech/sphinx) rather than a custom implementation
- Piotrowska et al., "The Loopix Anonymity System" (USENIX Security 2017) — per-hop continuous-time exponential mixing delay and drop-cover traffic design Sub-Phase 2B's `parda-mixnode` implements (`mixnode/src/mixing.rs`, `mixnode/src/cover_traffic.rs`)
- Krawczyk & Eronen, RFC 5869, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)" — the KDF Sub-Phase 3A's `self_destruct` module implements via the `hkdf` crate (RustCrypto), not a custom construction. See `docs/phase3-3a-self-destruct-design.md`.
- Signal, "Technology preview: Sealed sender for Signal" (signal.org/blog/sealed-sender, 2018) — the design Sub-Phase 2A's `parda_protocol::sealed_sender` module implements, via `libsignal-protocol`'s own `sealed_sender_encrypt`/`sealed_sender_decrypt`
- NIST SP 800-208 — Recommendation for Stateful Hash-Based Signature Schemes
- CNSA 2.0 Suite — NSA Commercial National Security Algorithm Suite 2.0
- RFC 9171, "Bundle Protocol Version 7" — the wire format `parda_mesh::bundle` implements via the `bp7` crate (`dtn7` org, Apache-2.0), not a custom bundle format. See `mesh/src/bundle.rs` module docs for why the `dtn7` daemon crate itself (same org) is not embedded.
- Langley, "Pond" (2012; design overview archived at `imperialviolet.org`) — prior art for a keyed/counter-derived "dead drop" storage identifier, the lineage `parda_protocol::dead_drop`'s address derivation follows. See `docs/phase4-4c-dead-drop-addressing-design.md` §1-2.
- Cheng et al., "Talek: Private Group Messaging with Hidden Access Patterns" (ACSAC 2020 / IACR ePrint 2020/066) — the formal "access sequence indistinguishability" property this phase's retrieval-pattern mitigation is scoped against and explicitly does not attempt to fully achieve (full PIR was considered and rejected as disproportionate — design note §3, §3a).
- Piotrowska et al., "The Loopix Anonymity System" (USENIX Security 2017) — also the direct model for Sub-Phase 4C's decoy-query retrieval-pattern mitigation (`parda_protocol::dead_drop::build_poll_set`), reusing the same "indistinguishable dummy traffic" pattern already implemented and tested for Sub-Phase 2B's cover traffic (`mixnode/src/cover_traffic.rs`).

---

*This threat model is part of a research prototype. It has not been reviewed by a certified security auditor.*
