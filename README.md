# PARDA — Privacy-Assured Resilient Defense Architecture

> **Tagline:** *Communication that leaves no trace.*

A metadata-resistant, end-to-end encrypted messaging system prototype designed for secure field communication. PARDA is an engineering research project exploring defense-grade privacy guarantees — it is **not** a certified operational military system.

---

## Table of Contents

- [Problem Statement](#problem-statement)
- [Core Features](#core-features)
- [Architecture Overview](#architecture-overview)
- [Tech Stack](#tech-stack)
- [Status & Limitations](#status--limitations)
- [Setup & Installation](#setup--installation)
- [Threat Model](#threat-model)
- [License](#license)
- [Contributing](#contributing)

---

## Problem Statement

Modern end-to-end encrypted (E2EE) messaging platforms — Signal, WhatsApp, Wire — protect message *content* effectively, but routinely leak **communication metadata**: who is talking to whom, when, how often, and from where. For personnel operating in adversarial environments, this metadata exposure is often more operationally dangerous than plaintext content.

Key attack surfaces that PARDA addresses:

| Threat | Existing E2EE Gap |
|--------|-------------------|
| Traffic analysis | Timing correlation across sender/receiver pairs remains possible even with E2EE |
| Metadata retention | Server-side logs of message timestamps, contact graphs, and delivery receipts |
| Forensic recovery | Message persistence on device storage beyond the intended retention window |
| Relay-node trust | Single-hop relay architecture means compromised servers expose the full social graph |
| Connectivity dependency | Centralized infrastructure fails in denied, degraded, or disconnected (D3) environments |

PARDA is designed to eliminate or mitigate each of these vectors through a combination of cryptographic primitives, mix-network routing, and offline-capable mesh dead-drop delivery.

---

## Core Features

### 🔐 End-to-End Encryption (E2EE)
- Built on the **Signal Protocol** (`libsignal-client`) — Double Ratchet Algorithm with X3DH key exchange
- Per-message ephemeral keys ensure forward secrecy and break-in recovery
- No plaintext ever leaves the originating device

### 🌐 Mix-Network Metadata Resistance
- Messages routed through a **Sphinx-packet mix network** (Loopix-inspired)
- Cover traffic generation to prevent traffic analysis
- Onion-layered routing with fixed-latency packet batching to defeat timing correlation
- No relay node learns both the sender and the final recipient

### 💣 Cryptographic Self-Destruct
- Messages are encrypted with a **time-bound key** derived from a KDF anchored to a delivery timestamp
- Key material is deterministically deleted post-expiry on all endpoints
- Optional **read-triggered destruction**: key erasure on first plaintext decode
- Backed by secure memory wiping (`zeroize` / `memzero`) to prevent cold-boot and swap recovery

### 📡 Offline Mesh Dead-Drop Mode
- Peer-to-peer **delay-tolerant networking (DTN)** store-and-forward relay for air-gapped or connectivity-denied environments
- Bluetooth Low Energy (BLE) and Wi-Fi Direct proximity channels
- Messages encrypted at rest and transmitted as anonymous "dead drops" using onion-addressed store locations
- Compatible with intermittent connectivity; no persistent server required

---

## Architecture Overview

PARDA is structured across four implementation phases:

```
Phase 1 — Core Cryptographic Layer
├── libsignal-client integration (X3DH + Double Ratchet)
├── Key store with hardware-backed secure enclave support
└── Zeroize-on-expiry self-destruct mechanism

Phase 2 — Mix-Network Routing
├── Sphinx packet construction and onion encryption
├── Mix node daemon with Poisson-sampled batching
└── Cover traffic scheduler

Phase 3 — Application Layer
├── Encrypted message store (SQLCipher)
├── Ephemeral session manager
└── CLI prototype + REST API gateway

Phase 4 — Offline Mesh Dead-Drop
├── BLE / Wi-Fi Direct proximity transport
├── DTN store-and-forward relay agent
└── Anonymous dead-drop addressing scheme
```

Each phase produces independently testable deliverables. Phases 1–3 target standard IP-connected environments; Phase 4 adds resilience for denied/degraded connectivity scenarios.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Encryption / Ratchet** | `libsignal-client` (Rust), `ring` |
| **Mix Routing** | `sphinx-packet` crate (Rust, Nym Technologies), Loopix-style per-hop delay + drop-cover traffic |
| **Transport** | gRPC (mTLS), optional Tor hidden service |
| **Offline Mesh** | BLE (BlueZ / CoreBluetooth), Wi-Fi Direct, `dtn7-rs` |
| **Secure Storage** | SQLCipher, OS-native Keystore (Android Keystore / iOS Secure Enclave) |
| **Backend Services** | Rust (Axum), Docker + Kubernetes |
| **Client** | Flutter (cross-platform mobile), CLI prototype (Rust) |
| **Testing** | Rust `cargo test`, Python property-based tests (`hypothesis`) |
| **CI/CD** | GitHub Actions |

---

## Status & Limitations

> ⚠️ **RESEARCH PROTOTYPE — NOT FOR OPERATIONAL DEPLOYMENT**

**Current phase: Phase 2 complete (Sub-Phase 2A + Sub-Phase 2B). Phase 3, Sub-Phase 3A (time-bound self-destruct key derivation + zeroize-on-expiry) implemented and tested — Sub-Phases 3B (read-triggered), 3C (swap/cold-boot hardening), and 3D (application layer) not yet started.**

Every ✅ below is backed by a named test — see `docs/THREAT_MODEL.md` §5 for the exact test each row cites. A property is never marked done on the strength of the implementation alone.

| Property | Status |
|----------|--------|
| Message confidentiality (Signal Protocol X3DH + Double Ratchet) | ✅ Phase 1 |
| Forward secrecy (per-message ephemeral keys) | ✅ Phase 1 |
| Break-in recovery (Double Ratchet self-healing) | ✅ Phase 1 (implementation-level; not separately adversarially tested — relies on upstream libsignal-protocol) |
| Hardware-backed key storage (Android Keystore / iOS Secure Enclave) | ✅ Phase 1 |
| Envelope wire-format versioning (explicit error on mismatch) | ✅ Sub-Phase 2A |
| Sender-receiver unlinkability **from the relay operator** (sealed sender) | ✅ Sub-Phase 2A |
| Relay store encrypted at rest (SQLCipher) | ✅ Sub-Phase 2A |
| Relay store survives restart | ✅ Sub-Phase 2A |
| Sender-receiver unlinkability under **network-level traffic timing analysis** (send path) | ✅ Sub-Phase 2B |
| Mix-network metadata resistance (Sphinx routing, per-hop mixing delay, drop-cover traffic) | ✅ Sub-Phase 2B |
| Mix routing degrades to loss/delay — never deanonymization — when a hop misbehaves | ✅ Sub-Phase 2B |
| Sender-receiver unlinkability under GPA observation of the **receive/fetch path** | 🔲 Not yet implemented |
| Time-bound self-destruct key derivation (HKDF, local secret — not the Double-Ratchet key, see limitations) | ✅ Sub-Phase 3A |
| Self-destruct key provably erased from live process memory at expiry | ✅ Sub-Phase 3A |
| Clock-rollback detection for expiry, fail-closed | ✅ Sub-Phase 3A |
| Read-triggered self-destruct | 🔲 Sub-Phase 3B |
| Self-destruct swap/cold-boot/forensic-recovery hardening | 🔲 Sub-Phase 3C |
| Offline mesh dead-drop | 🔲 Phase 4 |
| Post-quantum key encapsulation (ML-KEM) | 🔲 Phase 5 |

The following limitations apply and must be understood before any evaluation:

- **No CNSA 2.0 compliance.** Post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA) are not yet integrated. The current design uses classical elliptic-curve primitives only.
- **No FIPS 140-3 validation.** Cryptographic modules have not undergone formal FIPS certification.
- **No formal security audit.** The codebase has not been independently audited by a third-party cryptographic firm.
- **Not accredited for classified networks.** PARDA has no ATO (Authority to Operate), does not comply with RMF/DIACAP, and must not be used on any classified infrastructure.
- **Relay server still sees sender → recipient metadata for any envelope sent with `sealed_sender = false`** — true of every Phase 1 peer, and any Phase 2 peer that doesn't opt in for a given message.
- **Sealed sender hides identity, not IP address.** The relay still sees the connecting TCP source IP for the *final* mix hop, not the true sender's IP; sealed sender is an application-layer property, not a network-anonymity one on its own.
- **Sealed-sender certificate issuance has no account authentication behind it** — same Trust-On-First-Use posture Phase 1 already had for prekey bundle uploads. See `docs/THREAT_MODEL.md` §3.5.
- **No TLS in server binary or mix nodes.** Use a reverse proxy (nginx/Caddy) with a valid certificate in any networked deployment.
- **Side-channel mitigations are partial.** Constant-time implementations are targeted but not yet verified across all code paths.
- **Mix-network topology has no directory authority.** `MixTopology` is a static, trust-on-first-use configured list — same posture as prekey bundle upload and sealed-sender cert issuance. No freshness, revocation, or decentralized consensus. See `docs/THREAT_MODEL.md` §3.6, §4.
- **Mix routing anonymizes the send path only.** Fetching messages (`MixTransport::receive`) still talks to the relay directly, exactly like `DirectTransport` — the pull side is not yet anonymized. See `docs/THREAT_MODEL.md` §3.1, §3.6.
- **Cover traffic requires peer configuration.** A mix node with fewer than 3 configured `MIXNODE_PEERS` emits no cover traffic at all (logged, not silently degraded) — its real-traffic volume alone remains observable to a GPA at that node's edges.
- **The timing-correlation resistance claim is empirical, not a formal proof.** `mixnode/tests/timing_correlation_tests.rs` demonstrates no above-chance send/arrival correlation via a permutation test at a specific tested scale (path length, node count, delay parameters) — it does not establish anonymity at arbitrary traffic volumes or configurations. See `docs/THREAT_MODEL.md` §3.6.
- **Mix-node identity is ephemeral.** No persistent or hardware-backed mix-node identity exists yet (`mixnode/src/identity.rs`) — a restarted node's public key changes, breaking any peer's cached topology entry for it.
- **Self-destruct key is not literally derived from the Double-Ratchet message key.** Libsignal's public API never exposes that key to PARDA's code (confirmed by reading the pinned `v0.66.0` source) — reaching for it would mean forking libsignal or reimplementing decryption ourselves, both of which reopen the no-custom-crypto risk this project already rejected once. Instead, a fresh local secret is generated at decrypt time and HKDF-derives the self-destruct key; self-destruct is a per-device guarantee about the *recovered plaintext's* lifetime, not shared protocol state. See `docs/phase3-3a-self-destruct-design.md` §1.
- **Self-destruct clock trust has known, unsolved gaps.** A monotonic timer plus a persisted rollback-detection watermark defeats an adversary who changes the device's wall clock through ordinary means. **It does not defend against a rooted/jailbroken device that can also rewrite the persisted watermark file, nor against a device that's powered off and never allowed to run the app process again** — no user-space mechanism can fire if the process never executes. See `docs/phase3-3a-self-destruct-design.md` §3.
- **Self-destruct expiry is not yet proven against swap, hibernation, or cold-boot RAM extraction.** Sub-Phase 3A proves the key is gone from *live, resident* process memory (`protocol/src/self_destruct.rs` memory-forensics tests) — it says nothing about whether a copy was paged to disk before erasure ran. That's Sub-Phase 3C's job (`mlock`/swap-avoidance), not yet implemented.
- **An adversary with a memory dump taken before expiry fires always recovers the plaintext.** No cryptographic self-destruct scheme changes this; it isn't a gap specific to PARDA's implementation, but it's stated here because it's easy to imply otherwise by omission.

This project is published for research, academic review, and engineering demonstration purposes only.

---

## Components

| Directory | Description |
|-----------|-------------|
| [`/protocol`](protocol/) | Rust: libsignal-protocol wrapper (X3DH, Double Ratchet, key gen), sealed sender, Sphinx mix-network packet build/unwrap (`mixnet`), transport abstraction, time-bound self-destruct (`self_destruct`, `clock_guard`) |
| [`/server`](server/) | Rust/Axum: dumb-pipe relay server (store-and-forward), SQLCipher persistence, sealed-sender certificate authority |
| [`/mixnode`](mixnode/) | Rust/Axum: mix-network node daemon — Sphinx forwarding, per-hop mixing delay, drop-cover traffic (Sub-Phase 2B) |
| [`/mobile`](mobile/) | Flutter: cross-platform client with Android Keystore integration |
| [`/docs`](docs/) | Architecture decisions, threat model |

See [`docs/phase1-architecture.md`](docs/phase1-architecture.md) for stack decisions and tradeoffs.

---

## Setup & Installation

> 🚧 **Installation instructions will be added when Phase 1 is complete.**

### Prerequisites (planned)

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update stable

# Flutter SDK (for mobile client)
# See: https://flutter.dev/docs/get-started/install

# Docker (for mix node development environment)
docker --version  # >= 24.x recommended
```

### Build (placeholder)

```bash
git clone https://github.com/your-org/parda.git
cd parda
cargo build --release       # Core cryptographic layer
# docker compose up         # Mix node cluster (Phase 2)
# flutter build apk         # Android client (Phase 3)
```

*Full setup documentation will be maintained in [`docs/SETUP.md`](docs/SETUP.md) as each phase ships.*

---

## Threat Model

PARDA targets a threat model in which a **global passive adversary** can observe all network traffic, and an **active adversary** may compromise individual mix nodes or relay infrastructure, but cannot simultaneously compromise all nodes in a routing path or the sender/receiver endpoints. The system is designed to provide **sender-receiver unlinkability**, **message content confidentiality**, and **forward secrecy** under these conditions. Self-destruct mechanisms address the additional threat of **device seizure and forensic analysis** post-delivery. The system does *not* currently claim resistance to quantum adversaries or traffic analysis by adversaries with full mix-network compromise.

📄 Full threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — finalized for Phase 1 + Sub-Phase 2A + Sub-Phase 2B

---

## License

*License to be determined. Candidate: [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) or [MIT](https://opensource.org/licenses/MIT).*

`LICENSE` file will be added prior to the v0.1.0 release.

---

## Contributing

Contribution guidelines will be published in [`CONTRIBUTING.md`](CONTRIBUTING.md) before the v0.1.0 milestone.

In the interim, please open an issue to discuss proposed changes before submitting pull requests. All contributors must agree to the project's Contributor License Agreement (CLA) once published.

---

*PARDA is an engineering prototype. It makes no claims of certification, operational readiness, or compliance with any government security standard. Use at your own risk and only in accordance with applicable law.*
