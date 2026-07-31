# PARDA Threat Model

**Status:** Finalized for Phase 1 + Sub-Phase 2A; mix-network (Sub-Phase 2B) sections are a design target, not yet implemented — v0.2.0 | Last updated: 2026-07-31

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

---

## 3. Adversary Model

### 3.1 Global Passive Adversary (GPA)

The primary adversary can **observe all network traffic** on all links simultaneously — including encrypted packets, IP headers, and timing information. The GPA cannot break well-implemented cryptography but can perform traffic analysis.

**PARDA goal:** Sender-receiver unlinkability under GPA observation via mix-network routing and cover traffic (Sub-Phase 2B — **not yet implemented**; see §3.6).

**Current gap:** Nothing shipped so far defeats a GPA. Sealed sender (§3.5) removes sender identity from what the *relay itself* stores and logs, but a GPA watching the wire still sees: the TCP connection between a client and the relay (source IP), TLS record sizes/timing if TLS terminates close to the relay, and the `recipient_id` field, which sealed sender deliberately leaves plaintext for routing. A GPA who can also compromise or subpoena the relay learns exactly what the relay's own logs contain — nothing more, nothing less (see §3.5's precise boundary).

### 3.2 Active Relay-Node Adversary (Sub-Phase 2B mix network)

An adversary who **controls one or more mix nodes** in a Sub-Phase 2B routing path. Such an adversary may drop, delay, or replay packets but cannot learn the full routing path of any single Sphinx packet through an honest node.

**PARDA goal:** No single compromised mix node breaks anonymity; requires **all N nodes** in a message's path to collude to fully de-anonymize that message (see §3.6 for the precise per-hop guarantee — this is *not* the same as "N-1 colluding nodes," which overstates what a Sphinx/Loopix-style design actually provides).

**Status:** Not yet implemented. This section states the design target Sub-Phase 2B must be tested against, per the requirement that batching/cover-traffic parameters be threat-model outputs, not free variables chosen during implementation.

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

**PARDA goal:** Cryptographic self-destruct eliminates key material post-expiry; secure memory wiping prevents recovery from volatile storage. **Status:** Phase 3, not started. `self_destruct_at` remains an untouched stub field.

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

### 3.6 Sub-Phase 2B Mix-Network Adversary Capability Boundaries (design target — not yet implemented)

This section exists so that Sphinx packet batching, path-length, and cover-traffic parameters — chosen once 2B implementation starts — are answers to threat-model questions, not free variables picked for implementation convenience. It must be read before any batching constant is hardcoded.

**Compromise threshold:** For a message routed over a path of length N (N ≥ 3 per the Definition of Done), sender-receiver unlinkability for that message holds as long as **at least one node on its path is honest**. This is the standard Sphinx/Loopix per-message guarantee: each honest hop re-randomizes the packet's cryptographic appearance and (with cover traffic + batching) its timing correlation, so a single honest hop is sufficient to break the adversary's ability to link the packet's pre-hop and post-hop appearance. Equivalently: **all N nodes on a given message's path must collude** to fully deanonymize that specific message. (Note this is *per-message*: an adversary controlling most-but-not-all nodes network-wide still cannot deanonymize any message that happens to route through the one honest node it doesn't control — but with high compromise fractions, the *probability* that a random path avoids the honest set drops accordingly. That probability, not a fixed node count, is the real security parameter and must be computed for the deployed path-selection policy before it's trusted operationally.)

**What a Global Passive Adversary (§3.1) still learns even under full protocol correctness:**
- Aggregate traffic volume in and out of the mix network as a whole.
- That *some* client is active, from connection timing to its entry node (padded/cover traffic reduces but does not perfectly eliminate this at low traffic volumes — this is a Loopix-inherited limitation, not a PARDA-specific one).
- Anything visible at a node the GPA also controls (composing with §3.2).

**What a GPA does NOT get, as long as ≥1 honest hop exists on the path:**
- A confirmed sender→receiver pairing for a specific message, above the false-positive rate the statistical timing-correlation test (Definition of Done item) must demonstrate.

**Explicitly out of scope, still:** full mix-network compromise (§4) — if every node is adversary-controlled, PARDA makes no anonymity claim, matching Loopix's own stated limits.

---

## 4. Out of Scope (Current Phase)

- **Quantum adversaries:** Post-quantum key encapsulation (ML-KEM) and signatures (ML-DSA) are planned for a future phase. The current design uses X25519 and Ed25519. (`libsignal-protocol`'s Kyber prekey storage trait is implemented as an unused stub — see `protocol/src/store.rs` — solely because the pinned library version requires it structurally; no PQXDH handshake is performed.)
- **Full mix-network compromise:** PARDA does not claim anonymity if all nodes in a routing path are colluding (§3.6).
- **IP-address anonymity:** Sealed sender (§3.5) is an application-layer property; it does not hide connection-level metadata. That is Sub-Phase 2B's job, and even then only for traffic actually routed through the mix network.
- **Endpoint compromise prior to message creation:** If the sending device is compromised before message composition, no protocol-level protection applies.
- **Sealed-sender CA enrollment authentication:** see §3.5's trust-assumption paragraph.
- **Acoustic / physical side-channel attacks**
- **Denial-of-service resilience**

---

## 5. Security Properties Claimed

Every ✅ row below is backed by a named test a reviewer can run; nothing is marked done on the strength of the implementation alone.

| Property | Status | Evidence |
|----------|--------|----------|
| Message confidentiality (E2EE) | ✅ Implemented & tested — Phase 1 | `protocol/tests/crypto_tests.rs::test_double_ratchet_encrypt_decrypt_roundtrip` |
| Forward secrecy | ✅ Implemented & tested — Phase 1 | `protocol/tests/crypto_tests.rs::test_forward_secrecy_stale_ciphertext_rejected` |
| Break-in recovery | ✅ Implemented — Phase 1 (Double Ratchet self-healing is inherent to the libsignal session state machine used) | Not separately adversarially tested; relies on upstream libsignal-protocol correctness |
| Sender-receiver unlinkability **from the relay operator** | ✅ Implemented & tested — Sub-Phase 2A | `server/tests/sealed_sender_relay_tests.rs`, `protocol/tests/sealed_sender_tests.rs` |
| Sender-receiver unlinkability **under network-level GPA / traffic timing analysis** | 🔲 Planned — Sub-Phase 2B | Not started |
| Envelope wire-format version mismatch fails loud | ✅ Implemented & tested | `protocol/tests/crypto_tests.rs::test_envelope_future_version_rejected_explicitly`, `::test_envelope_missing_version_defaults_to_v1` |
| Relay store encrypted at rest | ✅ Implemented & tested — Sub-Phase 2A | `server/tests/persistence_tests.rs::test_database_file_is_not_plaintext_on_disk`, `::test_wrong_key_cannot_read_database` |
| Relay store survives restart | ✅ Implemented & tested — Sub-Phase 2A | `server/tests/persistence_tests.rs::test_data_survives_simulated_restart` |
| Metadata resistance (timing) | 🔲 Planned — Sub-Phase 2B | Not started |
| Cryptographic self-destruct | 🔲 Planned — Phase 3 | Not started |
| Post-quantum resistance | 🔲 Future (not in scope v0.x) | Not started |

---

## 6. References

- Cohn-Gordon et al., "A Formal Security Analysis of the Signal Messaging Protocol" (IEEE EuroS&P 2017)
- Piotrowska et al., "The Loopix Anonymity System" (USENIX Security 2017)
- Danezis & Goldberg, "Sphinx: A Compact and Provably Secure Mix Format" (IEEE S&P 2009) — reference for Sub-Phase 2B, not yet implemented
- Signal, "Technology preview: Sealed sender for Signal" (signal.org/blog/sealed-sender, 2018) — the design Sub-Phase 2A's `parda_protocol::sealed_sender` module implements, via `libsignal-protocol`'s own `sealed_sender_encrypt`/`sealed_sender_decrypt`
- NIST SP 800-208 — Recommendation for Stateful Hash-Based Signature Schemes
- CNSA 2.0 Suite — NSA Commercial National Security Algorithm Suite 2.0

---

*This threat model is part of a research prototype. It has not been reviewed by a certified security auditor.*
