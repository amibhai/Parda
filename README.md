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
- Peer-to-peer **delay-tolerant networking (DTN)** store-and-forward relay (RFC 9171 bundle framing) for air-gapped or connectivity-denied environments
- Bluetooth Low Energy (BLE) proximity channel — one real platform backend (Linux/`bluer`); Wi-Fi Direct proven at the protocol level only, no real platform binding exists yet (see Status & Limitations)
- Messages encrypted at rest and addressed via a blinded, HKDF-derived dead-drop tag (`protocol/src/dead_drop.rs`) — a carrier never sees sender or recipient identity
- Flood/Sybil-resistant store-and-forward relay agent: bounded storage, per-session admission caps, TTL expiry
- No persistent radio-layer advertisement identifier; decoy-query retrieval-pattern mitigation (measured, not perfect — see Status & Limitations)
- Compatible with intermittent connectivity; no persistent server required; hybrid online/mesh handoff with no manual mode switching

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
├── BLE / Wi-Fi Direct proximity transport (BLE: real on Linux, simulated elsewhere; Wi-Fi Direct: simulated only)
├── DTN store-and-forward relay agent (flood/Sybil-resistant)
└── Anonymous dead-drop addressing scheme (blinded, measured retrieval-pattern mitigation)
```

Each phase produces independently testable deliverables. Phases 1–3 target standard IP-connected environments; Phase 4 adds resilience for denied/degraded connectivity scenarios.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Encryption / Ratchet** | `libsignal-client` (Rust), `ring` |
| **Mix Routing** | `sphinx-packet` crate (Rust, Nym Technologies), Loopix-style per-hop delay + drop-cover traffic |
| **Transport** | gRPC (mTLS), optional Tor hidden service |
| **Offline Mesh** | BLE — `bluer`/BlueZ (Linux, real; CoreBluetooth/Android/Windows not implemented — see Status & Limitations), Wi-Fi Direct (proven at the protocol level via simulated large-MTU profile only — no real platform binding exists for any target, see Limitations), `bp7` (RFC 9171 bundle framing; not the `dtn7` daemon — see `mesh/src/bundle.rs`) |
| **Secure Storage** | SQLCipher, OS-native Keystore (Android Keystore / iOS Secure Enclave) |
| **Backend Services** | Rust (Axum), Docker + Kubernetes |
| **Client** | Flutter (cross-platform mobile), CLI prototype (Rust) |
| **Testing** | Rust `cargo test`, Python property-based tests (`hypothesis`) |
| **CI/CD** | GitHub Actions |

---

## Status & Limitations

> ⚠️ **RESEARCH PROTOTYPE — NOT FOR OPERATIONAL DEPLOYMENT**

**Current phase: Phase 2 complete (Sub-Phase 2A + Sub-Phase 2B). Phase 3 complete through Sub-Phase 3D: 3A (time-bound self-destruct key derivation + zeroize-on-expiry), 3B (read-triggered destruction), 3C (swap avoidance + forensic-recovery capstone test + mobile audit), and 3D (session-burn, client-side encrypted history store, REST gateway, CLI prototype) all implemented and tested. Phase 4 (Offline Mesh Dead-Drop) complete through Sub-Phase 4D: 4A (BLE proximity transport, one real backend + simulated), 4B (DTN store-and-forward relay agent, flood/Sybil resistance), 4C (blinded dead-drop addressing, measured retrieval-pattern mitigation), and 4D (multi-node simulation at scale, hybrid online/mesh handoff, combined field scenario, battery cost characterization) all implemented and tested — with, honestly, more new limitations surfaced than resolved, the same as Phase 3.

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
| Read-triggered self-destruct (no timer; erases on first read) | ✅ Sub-Phase 3B |
| Read-triggered destruction is atomic — no double-read, even under a race | ✅ Sub-Phase 3B |
| Derived key's memory locked against swap (`mlock`/`VirtualLock`) | ✅ Sub-Phase 3C |
| Forensic-recovery capstone test (simulated seizure, both modes) | ✅ Sub-Phase 3C |
| Mobile native-bridge audit | ✅ Sub-Phase 3C (findings below) |
| Self-destruct swap/cold-boot hardening beyond the derived key (plaintext buffer, hibernation) | 🔲 Not yet implemented |
| Session-level "burn this conversation" | ✅ Sub-Phase 3D (weaker guarantee than message self-destruct by necessity — see limitations) |
| Client-side encrypted message history store (SQLCipher), structurally excludes self-destructing messages | ✅ Sub-Phase 3D |
| CLI prototype — real X3DH, real HTTP transport, both self-destruct modes, session-burn | ✅ Sub-Phase 3D — actually run, not just compiled |
| REST API gateway (typed, versioned, dumb pipe) | ✅ Sub-Phase 3D |
| Self-destructing message surviving an app restart while pending | 🔲 Not yet implemented |
| No persistent radio-layer advertisement identifier (BLE) | ✅ Sub-Phase 4A |
| Real BLE backend (Linux/`bluer`) | ✅ Sub-Phase 4A (one platform — see limitations) |
| DTN store-and-forward relay agent, flood/Sybil-resistant | ✅ Sub-Phase 4B |
| Malicious-carrier storage opacity (mesh) | ✅ Sub-Phase 4B |
| Mesh partition/rejoin without duplication or silent loss | ✅ Sub-Phase 4B/4D |
| Blinded dead-drop addressing scheme | ✅ Sub-Phase 4C |
| Retrieval-pattern mitigation (decoy queries) — within-batch claim | ✅ Sub-Phase 4C (measured; cross-poll recurrence NOT mitigated — see limitations) |
| Self-destruct correctness under mesh latency | ✅ Sub-Phase 4C |
| Multi-node mesh simulation at scale (N=30, churn + partition) | ✅ Sub-Phase 4D |
| Hybrid online/mesh handoff | ✅ Sub-Phase 4D |
| Real CoreBluetooth / Android / Windows mesh backends | 🔲 Not implemented — documented gap, see limitations |
| Real Wi-Fi Direct platform binding | 🔲 Not implemented — no viable Rust crate found |
| Mesh mobile (Flutter) integration | 🔲 Out of scope this phase |
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
- **Read-triggered self-destruct has no timer at all — a message that is never read stays readable indefinitely.** This is the mode's documented contract (see `docs/phase3-3a-self-destruct-design.md` §5b), not an oversight; a caller wanting "expire by T or on read, whichever comes first" would need to combine both modes explicitly, which isn't implemented.
- **Self-destructing messages don't yet survive an app restart while still pending.** `SelfDestructingMessage` (both modes) is in-memory only — there is no restart-surviving holding area distinct from the main SQLCipher message store yet. That boundary is Sub-Phase 3D's job.
- **Only the derived key's memory is locked against swap — the decrypted plaintext buffer `open()` returns is not.** A caller holding that plaintext during a render window has a swap-exposure gap Sub-Phase 3C doesn't close. See `docs/phase3-3a-self-destruct-design.md` §8.
- **`mlock`/`VirtualLock` don't defend against hibernation**, which can snapshot locked pages to disk by design — a documented, inherent limitation of this class of mitigation, not specific to PARDA.
- **Memory-locking verification is asymmetric across platforms.** Linux locking is verified against the OS's own `/proc/self/status` accounting; Windows verification is limited to `VirtualLock`'s return code, since no equivalent low-friction per-process accounting API exists there.
- **The mobile Kotlin plaintext-clearing fix (Sub-Phase 3C) has not been runtime-verified against a real Flutter build.** No Android/Flutter toolchain was available when it was made; the reasoning is standard, documented Flutter platform-channel behavior, but "reasoned correct" and "verified correct" are different claims. See `docs/phase3-3a-self-destruct-design.md` §9.
- **The mobile app's Dart layer converts decrypted plaintext to a `String`**, which has no mutable backing storage in Dart — no zeroize discipline at any other layer can make this provably erasable as currently architected. This is a real constraint on Sub-Phase 3D's mobile self-destruct integration, not yet resolved.
- **No iOS native bridge exists.** `mobile/ios/` has no `SignalPlugin.swift` or equivalent — a pre-existing gap, not introduced by Phase 3, but relevant since Sub-Phase 3C's mobile audit could only cover Android.
- **"Burn this conversation" (session-level destruct) has a materially weaker guarantee than message-level self-destruct, and this is a hard limit, not a to-do.** `libsignal-protocol` v0.66.0's `PrivateKey` is a non-zeroizing `Copy` type (verified by reading `rust/core/src/curve.rs` in the pinned tag) — libsignal's own internals may hold implicit copies of session/identity key material that no code in this project can see or overwrite without forking libsignal, which would reopen the no-custom-crypto risk this project has declined twice now (§1 of the design note, and here). `burn_session` removes session/trust state from PARDA's own store — real and tested — but cannot claim byte-level erasure. See `docs/phase3-3a-self-destruct-design.md` §12.
- **Self-destructing messages still don't survive an app restart while pending.** `parda-client-store`'s write path structurally refuses to persist any self-destructing envelope (by design — persistence and destructibility are meant to be mutually exclusive per message), but no replacement restart-surviving holding area exists yet. A message that arrives while the app is closed and isn't read before the app is later killed is simply gone with no record.
- **The mobile Kotlin plaintext-clearing fix is still not runtime-verified against a real Flutter/Android build** — a different toolchain gap than the Rust workspace's vendored-SQLCipher/Perl requirement (`docs/phase1-architecture.md` §11 — now affects `parda-relay`, `parda-client-store`, and `parda-cli`), and not attempted this session.
- **The CLI's prekey-bundle exchange is in-process, not over real HTTP** — a deliberate scope decision (see `cli/src/main.rs` module docs), matching existing precedent in `server/tests/`. What the CLI does exercise over genuine HTTP is message send/receive, which is the sub-phase's actual point.
- **`parda-gateway` adds no auth, rate limiting, or request validation beyond what axum's `Json` extractor gives for free on the prekey-bundle routes.** It's an external-facing API surface where such things could grow, not a claim that they exist.
- **Raw radio-layer presence detection is unavoidable and not defended.** Rotation defeats re-identifying the same device across two encounters; it cannot and does not defeat detecting that a device is present during one. No software fix changes RF physics. See `docs/THREAT_MODEL.md` §3.7.
- **Real mesh backends exist for exactly one platform: Linux, via `bluer`/BlueZ.** CoreBluetooth (macOS/iOS), Android, and Windows are trait-ready (`parda_mesh::radio::MeshRadio`) but not implemented — no toolchain existed in the environment this phase was built in to write *and compile* real platform code against them, a materially weaker starting point than Phase 3's Kotlin fix (which edited an existing file without a toolchain; there was no existing BLE-peripheral Kotlin/Swift code here to extend). Documented as a gap, not shipped as untested stub code. See `mesh/src/radio/mod.rs` module docs.
- **The `bluer` real backend has not been compiled in this session.** It's gated `#[cfg(target_os = "linux")]` behind the `bluez` feature; the development machine is Windows, so local `cargo check` never touches it. Its first real compile happens in CI's `mesh-adversarial` job (Linux leg). Even once compiled, no GitHub-hosted CI runner has a Bluetooth radio, so `advertise`/`scan`/`connect`/`accept` are never exercised against real RF anywhere in this project's current pipeline.
- **App-level "MAC rotation" only ever means the advertised payload.** iOS hides the link-layer address from apps entirely (a random per-app `CBPeripheral` UUID instead of a MAC) and rotates it at the OS level on its own ~15-minute schedule with zero app control. Android's address randomization is OS/manufacturer policy, also with no fine-grained app control (observed absent entirely on some Samsung devices in prior published research). Linux/BlueZ's resolvable-private-address rotation is a kernel/`bluetoothd` privacy-subsystem setting. What `parda_mesh::radio::AdvertToken` rotation actually controls, on every platform, is the advertised payload only.
- **No real Wi-Fi Direct platform binding exists for any target platform.** No viable Rust crate was found (checked, not assumed) — the large-bundle-transfer path is proven at the protocol/relay level only, via `SimulatedMeshRadio`'s `SimProfile::WifiDirect` throughput profile.
- **Flood/Sybil resistance raises the cost of flooding; it does not eliminate it.** Because peers deliberately have no stable identity across sessions (the same property that defeats radio-layer tracking), classic per-identity rate limiting doesn't apply. The actual defense — a global storage cap plus a small per-connection-session admission cap — costs a determined attacker real time/energy to defeat by reconnecting repeatedly, but does not make it impossible. See `mesh/src/relay.rs` module docs.
- **Decoy-query retrieval-pattern mitigation has a measured, honest boundary.** It defeats identifying which address in a *single* poll batch is real (measured: `mesh/tests/retrieval_pattern_tests.rs::within_batch_real_address_is_not_identifiable_above_chance`). It does **not** hide a still-pending message's real address recurring, unchanged, across repeated polls — measured to make no statistically meaningful difference (`::cross_poll_recurrence_of_a_pending_address_is_not_hidden_by_decoys`, before/after accuracy within 2%). See `docs/phase4-4c-dead-drop-addressing-design.md` §3a and `docs/THREAT_MODEL.md` §3.7.2 for the full account, including the practical consequence (an adversary can re-link two otherwise radio-layer-unlinkable encounters via a slow-to-arrive message's recurring address).
- **Dead-drop address derivation uses a dedicated keypair, not the Double-Ratchet session or the Signal identity key** — the same "fresh, purpose-dedicated secret rather than reach into another protocol's internals" pattern already established for self-destruct's KDF (`docs/phase3-3a-self-destruct-design.md` §1) and applied here for the identical reason. See `docs/phase4-4c-dead-drop-addressing-design.md` §1.
- **A device-seizure adversary who recovers a conversation's dead-drop `tag_key` recovers every past and future address for it.** Inherent to any symmetric, deterministic addressing scheme where the recipient must be able to recompute addresses offline — not claimed to be otherwise. `tag_key` is protected only as well as the device's own key storage protects it, the same caveat every other long-lived key in this project already carries.
- **`dtn7` (the daemon crate) is not embedded — `bp7` (RFC 9171 CBOR framing only) is used instead, with PARDA's own store-and-forward/flood-resistance logic on top.** `dtn7` is self-described upstream as still under development and architected to run as a standalone daemon reached over REST/WebSocket, not as an embeddable library — pulling it in for this phase's most security-sensitive component would have reopened the same unaudited-assembly risk this project already declined twice for cryptographic code. See `mesh/src/bundle.rs` module docs.
- **Battery/resource cost is characterized by operation counts and wire-byte sizes, not real power draw.** `mesh/tests/battery_cost_tests.rs` measures concrete numbers at this crate's actual default parameters (e.g. 30 advertisement operations/hour and 540 advertisement-payload bytes/hour at the default 120s rotation interval) — no BLE hardware exists in the environment this phase was built in to measure milliwatt-level draw, and this is stated rather than approximated or omitted.
- **Mesh mode has no mobile UI or native bridge yet.** All Phase 4 work stays in the Rust workspace (`protocol`, `mesh`, and the tests that exercise them) — consistent with, and an addition to, the existing mobile gap list above (no iOS bridge, Kotlin fix unverified, Dart `String`-based plaintext handling).
- **Hybrid online/mesh handoff is proven against the real `MixTransport` type (with a deliberately unreachable topology) and a minimal in-memory mock standing in for `DirectTransport`, not a live mix network or relay.** A live Sub-Phase 2B mix network's own correctness is already `mixnode`'s test suite's responsibility (`mixnode/tests/timing_correlation_tests.rs` et al.) — re-proving it here would be duplicative. What `mesh/tests/combined_field_scenario_tests.rs` proves instead is that `HybridTransport` composes correctly with the real Phase 2 type and falls back to mesh exactly when that type's own `send` fails.

This project is published for research, academic review, and engineering demonstration purposes only.

---

## Components

| Directory | Description |
|-----------|-------------|
| [`/protocol`](protocol/) | Rust: libsignal-protocol wrapper (X3DH, Double Ratchet, key gen), sealed sender, Sphinx mix-network packet build/unwrap (`mixnet`), transport abstraction, time-bound + read-triggered self-destruct (`self_destruct`, `clock_guard`, `secure_memory`), session-burn, blinded dead-drop addressing (`dead_drop`, Sub-Phase 4C) |
| [`/server`](server/) | Rust/Axum: dumb-pipe relay server (store-and-forward), SQLCipher persistence, sealed-sender certificate authority |
| [`/mixnode`](mixnode/) | Rust/Axum: mix-network node daemon — Sphinx forwarding, per-hop mixing delay, drop-cover traffic (Sub-Phase 2B) |
| [`/gateway`](gateway/) | Rust/Axum: typed, versioned REST API gateway in front of `parda-relay` (Sub-Phase 3D) |
| [`/client-store`](client-store/) | Rust: client-side encrypted local message store (SQLCipher), structurally excludes self-destructing messages (Sub-Phase 3D) |
| [`/cli`](cli/) | Rust: CLI prototype exercising the full send/receive/self-destruct/burn flow end-to-end (Sub-Phase 3D) |
| [`/mesh`](mesh/) | Rust: offline mesh dead-drop — BLE proximity transport (`radio`, real backend on Linux/`bluer` + simulated), DTN store-and-forward relay agent (`relay`, `bundle`), `MeshTransport`/`HybridTransport`, multi-node simulation harness (`sim`) (Phase 4) |
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

PARDA targets a threat model in which a **global passive adversary** can observe all network traffic, and an **active adversary** may compromise individual mix nodes or relay infrastructure, but cannot simultaneously compromise all nodes in a routing path or the sender/receiver endpoints. The system is designed to provide **sender-receiver unlinkability**, **message content confidentiality**, and **forward secrecy** under these conditions. Self-destruct mechanisms address the additional threat of **device seizure and forensic analysis** post-delivery. Phase 4 adds a third adversary class, a **co-located passive/active radio observer** — BLE/Wi-Fi Direct are broadcast media, and no key management scheme changes that; PARDA minimizes what such an observer learns (content, sender/recipient linkage over time, retrieval-pattern correlation) and states plainly what it cannot fix (raw presence detection during an active session). The system does *not* currently claim resistance to quantum adversaries, traffic analysis by adversaries with full mix-network compromise, or full private-information-retrieval-strength hidden access patterns in mesh mode.

📄 Full threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — finalized for Phase 1 + Sub-Phase 2A + Sub-Phase 2B + Phase 3 (3A-3D) + Phase 4 (4A-4D)

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
