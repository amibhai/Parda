# PARDA Threat Model

**Status:** Finalized for Phase 1 + Sub-Phase 2A + Sub-Phase 2B — v0.3.0 | Last updated: 2026-07-31

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

**Status: Sub-Phase 3A implemented and tested (time-bound expiry, live-memory zeroization) — Sub-Phases 3B-3D not started.** `parda_protocol::self_destruct::SelfDestructingMessage` derives a fresh, local, time-bound key (HKDF-SHA256, `docs/phase3-3a-self-destruct-design.md`), re-encrypts the recovered plaintext under it (ChaCha20-Poly1305), and erases that key — provably, per
`protocol/src/self_destruct.rs`'s memory-forensics tests — when a monotonic-clock-anchored timer expires. **This is a genuinely narrower claim than the PARDA goal above states**, and the gap is specific:

- **What's proven:** the derived key is gone from *live, resident* process memory after expiry — not merely unreachable through the API. Proven two ways: reading the same live-typed reference immediately before/after the explicit zeroize call (`test_erase_zeroizes_before_clearing_and_ends_up_gone`), and, on Linux, scanning all of `/proc/self/mem` for the key's exact bytes before and after (`test_key_bytes_absent_from_process_memory_after_expiry`).
- **What's explicitly NOT yet proven or defended:** swap/pagefile recovery and cold-boot RAM extraction (Sub-Phase 3C's job — no `mlock`/swap-avoidance exists yet); read-triggered destruction (Sub-Phase 3B — only time-bound expiry is implemented); the mobile native-bridge audit (Sub-Phase 3C); and — critically for *this* adversary specifically — **an adversary who obtains a memory dump *before* expiry fires always gets the plaintext.** No cryptographic self-destruct scheme changes that; PARDA does not claim otherwise.
- **Clock trust (this adversary's core capability):** since this adversary has the device, they can change its wall clock. Primary defense is a monotonic (`Instant`) timer, immune to wall-clock changes for as long as the process runs; `clock_guard`'s persisted watermark detects and fails closed on a wall-clock rollback across a process restart. **Neither defends against a rooted/jailbroken device that can also rewrite the persisted watermark file directly, nor against a device that's powered off and never allowed to run the app process again** — both are stated plainly as unsolved in `docs/phase3-3a-self-destruct-design.md` §3, not glossed over.

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
| Read-triggered self-destruct | 🔲 Planned — Sub-Phase 3B | Not started |
| Swap/cold-boot/forensic-recovery hardening (`mlock`, memory dump test) | 🔲 Planned — Sub-Phase 3C | Not started |
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

---

*This threat model is part of a research prototype. It has not been reviewed by a certified security auditor.*
