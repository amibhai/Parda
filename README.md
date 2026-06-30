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
| **Mix Routing** | Sphinx packet library (Rust/Go), Loopix-derived scheduler |
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

**Current phase: Phase 1 — Core E2EE Messaging (in development)**

PARDA Phase 1 delivers a working 1:1 end-to-end encrypted messenger using the Signal Protocol. The following properties **are** provided in Phase 1:

| Property | Status |
|----------|--------|
| Message confidentiality (Signal Protocol X3DH + Double Ratchet) | ✅ Phase 1 |
| Forward secrecy (per-message ephemeral keys) | ✅ Phase 1 |
| Break-in recovery (Double Ratchet self-healing) | ✅ Phase 1 |
| Hardware-backed key storage (Android Keystore / iOS Secure Enclave) | ✅ Phase 1 |
| Cryptographic self-destruct | 🔲 Phase 3 |
| Sender-receiver unlinkability / sealed sender | 🔲 Phase 2 |
| Mix-network metadata resistance | 🔲 Phase 2 |
| Offline mesh dead-drop | 🔲 Phase 4 |
| Post-quantum key encapsulation (ML-KEM) | 🔲 Phase 5 |

The following limitations apply and must be understood before any evaluation:

- **No CNSA 2.0 compliance.** Post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA) are not yet integrated. The current design uses classical elliptic-curve primitives only.
- **No FIPS 140-3 validation.** Cryptographic modules have not undergone formal FIPS certification.
- **No formal security audit.** The codebase has not been independently audited by a third-party cryptographic firm.
- **Not accredited for classified networks.** PARDA has no ATO (Authority to Operate), does not comply with RMF/DIACAP, and must not be used on any classified infrastructure.
- **Relay server sees sender → recipient metadata in Phase 1.** Sealed-sender envelopes are a Phase 2 deliverable.
- **In-memory relay store.** Messages are lost on server restart. Persistent storage arrives in Phase 2.
- **No TLS in server binary.** Use a reverse proxy (nginx/Caddy) with a valid certificate in any networked deployment.
- **Side-channel mitigations are partial.** Constant-time implementations are targeted but not yet verified across all code paths.

This project is published for research, academic review, and engineering demonstration purposes only.

---

## Phase 1 Components

| Directory | Description |
|-----------|-------------|
| [`/protocol`](protocol/) | Rust: libsignal-protocol wrapper (X3DH, Double Ratchet, key gen) |
| [`/server`](server/) | Rust/Axum: dumb-pipe relay server (store-and-forward) |
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

📄 Full threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) *(draft — see Unreleased in CHANGELOG)*

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
