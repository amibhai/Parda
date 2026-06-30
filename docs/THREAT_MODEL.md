# PARDA Threat Model

**Status:** Draft — v0.0.1 | Last updated: 2026-06-30

---

## 1. Overview

This document defines the threat model for PARDA (Privacy-Assured Resilient Defense Architecture). It describes the assets being protected, the assumed adversary capabilities, and the security guarantees the system aims to provide. This is a living document and will be revised as the architecture matures.

---

## 2. Assets

| Asset | Description |
|-------|-------------|
| Message content | The plaintext payload of any communication |
| Communication metadata | Sender identity, receiver identity, timing, frequency, message size |
| Identity keys | Long-term identity key pairs (IK) used in X3DH |
| Session keys | Ephemeral Double Ratchet keys |
| Device state | Local message store, key material on disk |

---

## 3. Adversary Model

### 3.1 Global Passive Adversary (GPA)

The primary adversary can **observe all network traffic** on all links simultaneously — including encrypted packets, IP headers, and timing information. The GPA cannot break well-implemented cryptography but can perform traffic analysis.

**PARDA goal:** Sender-receiver unlinkability under GPA observation via mix-network routing and cover traffic.

### 3.2 Active Relay Adversary

An adversary who **controls one or more mix nodes** in the routing path. Such an adversary may drop, delay, or replay packets but cannot learn the full routing path of any single Sphinx packet.

**PARDA goal:** No single compromised mix node breaks anonymity; requires ≥ N-1 colluding nodes (where N = path length) to de-anonymize a message.

### 3.3 Server-Side Compromise

An adversary who **fully compromises a relay server or key distribution service**. Cannot decrypt past messages due to forward secrecy (Double Ratchet). Cannot forge messages without the sender's ephemeral key.

**PARDA goal:** Forward secrecy and break-in recovery via per-message ephemeral keys.

### 3.4 Device Seizure Adversary

An adversary with **physical access to a device** after message delivery. May attempt forensic recovery of message content from storage, swap space, or memory.

**PARDA goal:** Cryptographic self-destruct eliminates key material post-expiry; secure memory wiping prevents recovery from volatile storage.

---

## 4. Out of Scope (Current Phase)

- **Quantum adversaries:** Post-quantum key encapsulation (ML-KEM) and signatures (ML-DSA) are planned for a future phase. The current design uses X25519 and Ed25519.
- **Full mix-network compromise:** PARDA does not claim anonymity if all nodes in a routing path are colluding.
- **Endpoint compromise prior to message creation:** If the sending device is compromised before message composition, no protocol-level protection applies.
- **Acoustic / physical side-channel attacks**
- **Denial-of-service resilience**

---

## 5. Security Properties Claimed

| Property | Status |
|----------|--------|
| Message confidentiality (E2EE) | Planned — Phase 1 |
| Forward secrecy | Planned — Phase 1 |
| Break-in recovery | Planned — Phase 1 |
| Sender-receiver unlinkability | Planned — Phase 2 |
| Metadata resistance (timing) | Planned — Phase 2 |
| Cryptographic self-destruct | Planned — Phase 1 |
| Post-quantum resistance | Future (not in scope v0.x) |

---

## 6. References

- Cohn-Gordon et al., "A Formal Security Analysis of the Signal Messaging Protocol" (IEEE EuroS&P 2017)
- Piotrowska et al., "The Loopix Anonymity System" (USENIX Security 2017)
- NIST SP 800-208 — Recommendation for Stateful Hash-Based Signature Schemes
- CNSA 2.0 Suite — NSA Commercial National Security Algorithm Suite 2.0

---

*This threat model is part of a research prototype. It has not been reviewed by a certified security auditor.*
