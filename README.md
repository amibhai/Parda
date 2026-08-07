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

**Current phase: Phase 2 complete (Sub-Phase 2A + Sub-Phase 2B). Phase 3 complete through Sub-Phase 3D: 3A (time-bound self-destruct key derivation + zeroize-on-expiry), 3B (read-triggered destruction), 3C (swap avoidance + forensic-recovery capstone test + mobile audit), and 3D (session-burn, client-side encrypted history store, REST gateway, CLI prototype) all implemented and tested. Phase 4 (Offline Mesh Dead-Drop) complete through Sub-Phase 4D: 4A (BLE proximity transport, one real backend + simulated), 4B (DTN store-and-forward relay agent, flood/Sybil resistance), 4C (blinded dead-drop addressing, measured retrieval-pattern mitigation), and 4D (multi-node simulation at scale, hybrid online/mesh handoff, combined field scenario, battery cost characterization) all implemented and tested — with, honestly, more new limitations surfaced than resolved, the same as Phase 3. **Phase 4.5 (consolidation) is complete** — all five sub-phases: 4.5A (receive-path mix anonymization, closing the gap where the project's own headline claim, "no relay node learns both the sender and the final recipient," was false for the fetch half of every conversation), 4.5B (real Android BLE mesh backend behind a purpose-built Rust↔JNI bridge, built and run on a real emulator), 4.5C (native zeroize-on-release plaintext buffer replacing the unerasable Dart `String`, plus an uncompiled-by-necessity iOS bridge), 4.5D (unified trust bootstrapping — safety-number-style fingerprints replacing three separate undocumented TOFU postures), and 4.5E (operational hardening: TLS, gateway auth and rate limiting, self-destruct restart survival, combined expiry mode, mix-node identity persistence). Phase 4.5 resolved more than it added, unlike Phases 3 and 4 — but three of its five sub-phases still ship with limitations narrower than their goal, each stated explicitly below rather than rounded up.

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
| Sender-receiver unlinkability under GPA observation of the **receive/fetch path** | ✅ Sub-Phase 4.5A (mix-routed pull request; retrieval leg's own IP-visibility to the relay is a documented residual, not eliminated — see limitations) |
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
| Self-destructing message surviving an app restart while pending | ✅ Sub-Phase 4.5E (opt-in per message; the derived key now touches disk — a real trade-off, see limitations) |
| Combined "expire by T **or** on read, whichever comes first" self-destruct mode | ✅ Sub-Phase 4.5E |
| Out-of-band identity verification (safety-number-style fingerprints), MITM detected after verification | ✅ Sub-Phase 4.5D (first contact remains unprotected — inherent to TOFU, see limitations) |
| TLS termination for relay / mix node / gateway (native rustls) | ✅ Sub-Phase 4.5E (opt-in; plaintext remains the default — see limitations) |
| Gateway API-key authentication + rate limiting | ✅ Sub-Phase 4.5E (opt-in; open by default — see limitations) |
| Persistent mix-node identity across restarts | ✅ Sub-Phase 4.5E |
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
| Real Android BLE mesh backend (Rust↔JNI bridge + Kotlin `MeshBridge`) | ✅ Sub-Phase 4.5B — compiles, links, and loads on a real emulator; **BLE advertise/scan never exercised against real or virtual RF**, see limitations |
| Real CoreBluetooth (iOS/macOS) mesh backend | ⚠️ Sub-Phase 4.5C — Swift written against the real CoreBluetooth API, **never compiled, never run** (no macOS/Xcode exists in this environment), see limitations |
| Real Windows mesh backend | 🔲 Not implemented — documented gap, see limitations |
| Real Wi-Fi Direct platform binding | 🔲 Not implemented — no viable Rust crate found |
| Decrypted plaintext held in a native zeroize-on-release buffer, not a Dart `String` | ✅ Sub-Phase 4.5C (narrows the window to one render pass; does not eliminate it — see limitations) |
| Mesh mobile (Flutter) integration | ⚠️ Sub-Phase 4.5B — plugin, JNI bridge, and permissions wired and building; **not driven from the Dart UI**, see limitations |
| Post-quantum key encapsulation (ML-KEM) | 🔲 Phase 5 |

The following limitations apply and must be understood before any evaluation:

- **No CNSA 2.0 compliance.** Post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA) are not yet integrated. The current design uses classical elliptic-curve primitives only.
- **No FIPS 140-3 validation.** Cryptographic modules have not undergone formal FIPS certification.
- **No formal security audit.** The codebase has not been independently audited by a third-party cryptographic firm.
- **Not accredited for classified networks.** PARDA has no ATO (Authority to Operate), does not comply with RMF/DIACAP, and must not be used on any classified infrastructure.
- **Relay server still sees sender → recipient metadata for any envelope sent with `sealed_sender = false`** — true of every Phase 1 peer, and any Phase 2 peer that doesn't opt in for a given message.
- **Sealed sender hides identity, not IP address.** The relay still sees the connecting TCP source IP for the *final* mix hop, not the true sender's IP; sealed sender is an application-layer property, not a network-anonymity one on its own.
- **Sealed-sender certificate issuance has no account authentication behind it** — same Trust-On-First-Use posture Phase 1 already had for prekey bundle uploads. See `docs/THREAT_MODEL.md` §3.5.
- **TLS exists but is opt-in, so the default configuration still speaks plaintext HTTP.** Sub-Phase 4.5E adds native rustls termination to `parda-relay`, `parda-mixnode`, and `parda-gateway` (`parda-tls`), tested by real handshakes against real listeners (`tls/tests/tls_integration_tests.rs`). It activates only with `PARDA_TLS_ENABLED=1`; without it every request is readable by anyone on the network path. The default was left as-is deliberately — every existing integration test in the workspace connects over `http://` to a real loopback socket, and flipping the default would have made a large untested change while claiming to be a hardening step — and startup logs a warning whenever TLS is off. With TLS on but no certificate configured, a self-signed one is generated: that stops passive eavesdropping only, never an active MITM who can present their own. See `tls/src/lib.rs` module docs.
- **Side-channel mitigations are partial.** Constant-time implementations are targeted but not yet verified across all code paths.
- **Mix-network topology has no directory authority.** `MixTopology` is a static, trust-on-first-use configured list — same posture as prekey bundle upload and sealed-sender cert issuance. No freshness, revocation, or decentralized consensus. See `docs/THREAT_MODEL.md` §3.6, §4.
- **Mix-network topology has no directory authority, and mix-node key verification is a documented workflow rather than an enforced control.** Sub-Phase 4.5D's `parda_protocol::trust` provides the fingerprint primitive an operator could use to verify a mix node's key out-of-band (`TrustStore` is keyed by an opaque peer ID, tested against a mix-node-shaped identifier in `trust_bootstrapping_tests.rs`), but no mixnode call site invokes it — there is no discovery mechanism and no UI/CLI verification flow. See `docs/phase4.5d-trust-bootstrapping-design.md` §3.
- **Cover traffic requires peer configuration.** A mix node with fewer than 3 configured `MIXNODE_PEERS` emits no cover traffic at all (logged, not silently degraded) — its real-traffic volume alone remains observable to a GPA at that node's edges.
- **The timing-correlation resistance claim is empirical, not a formal proof.** `mixnode/tests/timing_correlation_tests.rs` demonstrates no above-chance send/arrival correlation via a permutation test at a specific tested scale (path length, node count, delay parameters) — it does not establish anonymity at arbitrary traffic volumes or configurations. See `docs/THREAT_MODEL.md` §3.6.
- **Mix-node identity persists across restarts, but is not hardware-backed and there is still no directory authority.** With `MIXNODE_KEY_PATH` set, a node generates and reuses a key file so its public key survives a restart (`mixnode/src/identity.rs`, tested). Without it, the key is still ephemeral and every restart invalidates peers' configured topology entries. The key file is created mode `0600` on Unix; **on Windows it is written with default permissions**, because there is no equivalent one-call permission bit and doing it properly needs an ACL API this crate does not otherwise use.
- **Self-destruct key is not literally derived from the Double-Ratchet message key.** Libsignal's public API never exposes that key to PARDA's code (confirmed by reading the pinned `v0.66.0` source) — reaching for it would mean forking libsignal or reimplementing decryption ourselves, both of which reopen the no-custom-crypto risk this project already rejected once. Instead, a fresh local secret is generated at decrypt time and HKDF-derives the self-destruct key; self-destruct is a per-device guarantee about the *recovered plaintext's* lifetime, not shared protocol state. See `docs/phase3-3a-self-destruct-design.md` §1.
- **Self-destruct clock trust has known, unsolved gaps.** A monotonic timer plus a persisted rollback-detection watermark defeats an adversary who changes the device's wall clock through ordinary means. **It does not defend against a rooted/jailbroken device that can also rewrite the persisted watermark file, nor against a device that's powered off and never allowed to run the app process again** — no user-space mechanism can fire if the process never executes. See `docs/phase3-3a-self-destruct-design.md` §3.
- **Self-destruct expiry is not yet proven against swap, hibernation, or cold-boot RAM extraction.** Sub-Phase 3A proves the key is gone from *live, resident* process memory (`protocol/src/self_destruct.rs` memory-forensics tests) — it says nothing about whether a copy was paged to disk before erasure ran. That's Sub-Phase 3C's job (`mlock`/swap-avoidance), not yet implemented.
- **An adversary with a memory dump taken before expiry fires always recovers the plaintext.** No cryptographic self-destruct scheme changes this; it isn't a gap specific to PARDA's implementation, but it's stated here because it's easy to imply otherwise by omission.
- **Read-triggered self-destruct has no timer at all — a message that is never read stays readable indefinitely.** This is that mode's documented contract (see `docs/phase3-3a-self-destruct-design.md` §5b), not an oversight. A caller wanting "expire by T **or** on read, whichever comes first" should use `DestructMode::Combined` (`seal_combined`, Sub-Phase 4.5E), which arms both mechanisms at once.
- **Only the derived key's memory is locked against swap — the decrypted plaintext buffer `open()` returns is not.** A caller holding that plaintext during a render window has a swap-exposure gap Sub-Phase 3C doesn't close. See `docs/phase3-3a-self-destruct-design.md` §8.
- **`mlock`/`VirtualLock` don't defend against hibernation**, which can snapshot locked pages to disk by design — a documented, inherent limitation of this class of mitigation, not specific to PARDA.
- **Memory-locking verification is asymmetric across platforms.** Linux locking is verified against the OS's own `/proc/self/status` accounting; Windows verification is limited to `VirtualLock`'s return code, since no equivalent low-friction per-process accounting API exists there.
- **The mobile Kotlin plaintext-clearing fix (Sub-Phase 3C) now compiles against the real Android SDK, but its runtime path has still never been executed.** Sub-Phase 4.5B scaffolded the Android project and built a real debug APK, which surfaced two genuine pre-existing defects in `SignalPlugin.kt` that no amount of reading had caught: `KeyHelper.generatePreKeys(start, count)` does not exist in any current libsignal-android release (confirmed against the source at the pinned tag), and `CiphertextMessage` was never imported. Both are fixed. "Compiles against the real SDK" and "the zeroize path was observed running" remain different claims, and only the first is made here.
- **Flutter's platform channel hands back an *unmodifiable* `Uint8List`, so the Dart-side copy of a decrypted message cannot be scrubbed by app code.** Found on the Pixel 8: the code zeroed that buffer unconditionally, which threw `UnsupportedError` inside `renderCopy` and meant *no received message ever rendered* — it showed a permanent "…" instead. Zeroing is now best-effort. The security consequence is real and unsolved: that buffer persists until Dart's GC reclaims it, which is an addition to the `String` residual below rather than a replacement for it. Copying into a modifiable list first would make it worse — two copies, the original still unscrubable.
- **The Dart plaintext gap is narrowed, not closed.** Sub-Phase 4.5C moves decrypted content into a native zeroize-on-release buffer (`parda_protocol::plaintext_ffi::PlaintextHandle`, reusing `self_destruct`/`secure_memory`'s already-audited discipline) reached through JNI, so `decryptMessage` now returns an opaque handle instead of raw bytes and `SessionService` never caches a decrypted `String`. **Flutter's `Text` widget still takes a Dart `String`** — there is no public Flutter API to render from a native buffer — so a transient `String` still materializes per render and lives as long as whatever holds it. The window goes from "the whole app session" to "one render pass, until the app is backgrounded"; a memory dump taken inside that window still finds the plaintext. See `docs/phase4.5c-dart-plaintext-design.md` §1 and §4.
- **The iOS bridge exists but has never been compiled or run — categorically, not "not yet."** `mobile/ios/Runner/SignalPlugin.swift` and `CoreBluetoothMeshRadio.swift` are written against Signal's real `LibSignalClient` Swift package and the real CoreBluetooth API, and are labeled as unverified in their own headers. No macOS or Xcode exists in this environment and no path to one does. Treat this code as a reviewed design sketch, not as working software. Writing it did surface two real CoreBluetooth findings recorded there: a backgrounded iOS peripheral's advertisement is stripped by the OS to the service-UUID overflow area only, and `CBPeripheralManager.startAdvertising` does not support service-data payloads *at all* — foreground or background — so the `AdvertToken` payload would have to move to a GATT characteristic read on iOS specifically.
- **Out-of-band identity verification does not protect first contact, and no verification UI exists.** Sub-Phase 4.5D detects an identity-key substitution *after* a peer has been marked `Verified` (`PardaError::IdentityKeyChangedAfterVerification`, tested on both the prekey-bundle and sealed-sender paths). A MITM present at first contact still succeeds — TOFU pins whatever key arrived first, exactly as before and exactly as in any TOFU scheme including Signal's — and `trust_bootstrapping_tests.rs` asserts that weakness deliberately so the documentation stays honest under test. The fingerprint construction is HKDF-SHA256 over both sorted identity keys, displayed as 60 digits: **inspired by Signal's safety numbers, explicitly not bit-compatible with them**, since re-deriving Signal's exact iterated-SHA-512 algorithm from memory risked getting a security-relevant detail subtly wrong. `TrustStore::record_verified` is the seam a future UI would call; this phase ships no such UI, so verification is currently only reachable from code. See `docs/phase4.5d-trust-bootstrapping-design.md`.
- **"Burn this conversation" (session-level destruct) has a materially weaker guarantee than message-level self-destruct, and this is a hard limit, not a to-do.** `libsignal-protocol` v0.66.0's `PrivateKey` is a non-zeroizing `Copy` type (verified by reading `rust/core/src/curve.rs` in the pinned tag) — libsignal's own internals may hold implicit copies of session/identity key material that no code in this project can see or overwrite without forking libsignal, which would reopen the no-custom-crypto risk this project has declined twice now (§1 of the design note, and here). `burn_session` removes session/trust state from PARDA's own store — real and tested — but cannot claim byte-level erasure. See `docs/phase3-3a-self-destruct-design.md` §12.
- **Self-destructing messages now survive a restart, at a real and specific cost: the derived key touches disk.** Sub-Phase 4.5E adds an opt-in holding area (`LocalMessageStore::stage_self_destructing`, a separate `pending_self_destruct` table — `store_message`'s structural refusal of self-destructing envelopes is untouched). Because forward secrecy already consumed the Double-Ratchet step-key on first decrypt, the message cannot be re-derived from its envelope; what has to persist is the *already-sealed* state, which necessarily includes the derived key. That key is written SQLCipher-encrypted, the same trust boundary as everything else in that store and never weaker — but "encrypted at rest under a key the device also holds" is categorically not the claim Sub-Phase 3A made, which was that the key never touches disk at all. An adversary who compromises the client-store key and images the disk during the message's live window recovers the plaintext; against the unpersisted primitive they would have had to image volatile memory instead. Staging is per message and never automatic. Restores are guarded by `clock_guard` (a rollback across the restart is refused) and downtime counts against the deadline. See `parda_protocol::self_destruct::PersistedSelfDestructState` and `client-store/tests/restart_survival_tests.rs`.
- **The CLI's prekey-bundle exchange is in-process, not over real HTTP** — a deliberate scope decision (see `cli/src/main.rs` module docs), matching existing precedent in `server/tests/`. What the CLI does exercise over genuine HTTP is message send/receive, which is the sub-phase's actual point.
- **`parda-gateway` now has API-key auth and rate limiting, both opt-in and therefore off by default.** Bearer keys are checked in constant time (`subtle::ConstantTimeEq` — a byte-by-byte early-exit comparison against a secret leaks its prefix through timing) against `PARDA_GATEWAY_API_KEYS`; with none configured, every request is accepted, exactly as before Sub-Phase 4.5E, and startup logs a warning saying so. **An API key authenticates the API client, not a human** — PARDA has no accounts, and adding real user authentication at the gateway would create precisely the metadata concentration point the rest of the project avoids. The token-bucket limiter is per-process and in-memory: restarting resets every bucket and two instances behind a load balancer do not share state, so it bounds casual abuse, not a distributed attacker. `/health` is deliberately outside the auth layer. See `gateway/src/auth.rs`.
- **Raw radio-layer presence detection is unavoidable and not defended.** Rotation defeats re-identifying the same device across two encounters; it cannot and does not defeat detecting that a device is present during one. No software fix changes RF physics. See `docs/THREAT_MODEL.md` §3.7.
- **The Android mesh backend now genuinely advertises over real Bluetooth LE, verified on a Pixel 8 — but a two-device exchange has still never been observed.** Running it on hardware found three bugs that compiling could not: (1) `JNIEnv::find_class` resolves against the *calling thread's* class loader, and a natively-attached tokio thread gets the system loader, so every Rust→Kotlin call raised `ClassNotFoundException` — mesh mode could never have started, and the class is now cached in `JNI_OnLoad`; (2) `MeshNode` never called `advertise()` at all (its loops only scan and accept — every test seeded a token directly into `SimNetwork`), so the device scanned while remaining permanently invisible; (3) a 128-bit service UUID plus a 16-byte rotating token is 57 bytes into a 31-byte legacy advertisement, so it failed with `ADVERTISE_FAILED_DATA_TOO_LARGE` every time and now uses LE extended advertising. **Verified:** `dumpsys bluetooth_manager` shows `com.parda.app` as an active advertiser, `Legacy: false`, `Connectable: true`, no device name, service data carrying the token. **Still not verified, and not claimed:** two devices actually discovering each other and completing a bundle exchange — this project has never had two devices running it at once — and the passive-scanner correlation test has never been run against the Android backend on real radio. Where LE extended advertising is unsupported, mesh mode now fails loudly rather than falling back to advertising a bare static UUID, which would be exactly the persistent radio-layer identifier Sub-Phase 4A prohibits. Windows remains unimplemented; iOS is the never-compiled sketch described above.
- **The `bluer` real backend has not been compiled in this session.** It's gated `#[cfg(target_os = "linux")]` behind the `bluez` feature; the development machine is Windows, so local `cargo check` never touches it. Its first real compile happens in CI's `mesh-adversarial` job (Linux leg). Even once compiled, no GitHub-hosted CI runner has a Bluetooth radio, so `advertise`/`scan`/`connect`/`accept` are never exercised against real RF anywhere in this project's current pipeline.
- **App-level "MAC rotation" only ever means the advertised payload.** iOS hides the link-layer address from apps entirely (a random per-app `CBPeripheral` UUID instead of a MAC) and rotates it at the OS level on its own ~15-minute schedule with zero app control. Android's address randomization is OS/manufacturer policy, also with no fine-grained app control (observed absent entirely on some Samsung devices in prior published research). Linux/BlueZ's resolvable-private-address rotation is a kernel/`bluetoothd` privacy-subsystem setting. What `parda_mesh::radio::AdvertToken` rotation actually controls, on every platform, is the advertised payload only.
- **No real Wi-Fi Direct platform binding exists for any target platform.** No viable Rust crate was found (checked, not assumed) — the large-bundle-transfer path is proven at the protocol/relay level only, via `SimulatedMeshRadio`'s `SimProfile::WifiDirect` throughput profile.
- **Flood/Sybil resistance raises the cost of flooding; it does not eliminate it.** Because peers deliberately have no stable identity across sessions (the same property that defeats radio-layer tracking), classic per-identity rate limiting doesn't apply. The actual defense — a global storage cap plus a small per-connection-session admission cap — costs a determined attacker real time/energy to defeat by reconnecting repeatedly, but does not make it impossible. See `mesh/src/relay.rs` module docs.
- **Decoy-query retrieval-pattern mitigation has a measured, honest boundary.** It defeats identifying which address in a *single* poll batch is real (measured: `mesh/tests/retrieval_pattern_tests.rs::within_batch_real_address_is_not_identifiable_above_chance`). It does **not** hide a still-pending message's real address recurring, unchanged, across repeated polls — measured to make no statistically meaningful difference (`::cross_poll_recurrence_of_a_pending_address_is_not_hidden_by_decoys`, before/after accuracy within 2%). See `docs/phase4-4c-dead-drop-addressing-design.md` §3a and `docs/THREAT_MODEL.md` §3.7.2 for the full account, including the practical consequence (an adversary can re-link two otherwise radio-layer-unlinkable encounters via a slow-to-arrive message's recurring address).
- **Dead-drop address derivation uses a dedicated keypair, not the Double-Ratchet session or the Signal identity key** — the same "fresh, purpose-dedicated secret rather than reach into another protocol's internals" pattern already established for self-destruct's KDF (`docs/phase3-3a-self-destruct-design.md` §1) and applied here for the identical reason. See `docs/phase4-4c-dead-drop-addressing-design.md` §1.
- **A device-seizure adversary who recovers a conversation's dead-drop `tag_key` recovers every past and future address for it.** Inherent to any symmetric, deterministic addressing scheme where the recipient must be able to recompute addresses offline — not claimed to be otherwise. `tag_key` is protected only as well as the device's own key storage protects it, the same caveat every other long-lived key in this project already carries.
- **`dtn7` (the daemon crate) is not embedded — `bp7` (RFC 9171 CBOR framing only) is used instead, with PARDA's own store-and-forward/flood-resistance logic on top.** `dtn7` is self-described upstream as still under development and architected to run as a standalone daemon reached over REST/WebSocket, not as an embeddable library — pulling it in for this phase's most security-sensitive component would have reopened the same unaudited-assembly risk this project already declined twice for cryptographic code. See `mesh/src/bundle.rs` module docs.
- **Battery/resource cost is characterized by operation counts and wire-byte sizes, not real power draw.** `mesh/tests/battery_cost_tests.rs` measures concrete numbers at this crate's actual default parameters (e.g. 30 advertisement operations/hour and 540 advertisement-payload bytes/hour at the default 120s rotation interval) — no BLE hardware exists in the environment this phase was built in to measure milliwatt-level draw, and this is stated rather than approximated or omitted.
- **Mesh mode has a native bridge but still no mobile UI.** `MeshPlugin.kt` exposes `startMesh`/`stopMesh` over a method channel and the manifest declares the Android 12+ runtime BLE permissions, but nothing in `mobile/lib/` requests those permissions or invokes either method — so on a real device the mesh bridge is reachable in principle and dormant in practice.
- **Hybrid online/mesh handoff is proven against the real `MixTransport` type (with a deliberately unreachable topology) and a minimal in-memory mock standing in for `DirectTransport`, not a live mix network or relay.** A live Sub-Phase 2B mix network's own correctness is already `mixnode`'s test suite's responsibility (`mixnode/tests/timing_correlation_tests.rs` et al.) — re-proving it here would be duplicative. What `mesh/tests/combined_field_scenario_tests.rs` proves instead is that `HybridTransport` composes correctly with the real Phase 2 type and falls back to mesh exactly when that type's own `send` fails.

- **Receive-path anonymization (Sub-Phase 4.5A) protects `recipient_id` from the wire, not the retrieval leg's IP address.** `MixTransport::receive`'s leg 2 (`GET /v1/pulls/{rendezvous_token}`) is a direct connection to the relay — it reveals no recipient identity (the token is unlinkable and freshly random), but it does reveal the client's IP to the relay at that moment. Same class of residual already accepted for sealed sender ("hides identity, not IP") and for mix-routed send (the client's own connection to its first mix hop is visible) — not a new or worse gap, but not full Loopix-style unlinkability either. See `docs/phase4.5a-receive-path-design.md` §1 and §3 for why Sphinx SURBs and an always-reachable client listener were both rejected as disproportionate to this sub-phase.
- **The new `/v1/pulls` relay-side staging table is not a new trust boundary, but is a new piece of state.** It holds recently-fetched envelopes keyed by an unlinkable token for up to 5 minutes (`PULL_STAGE_TTL_MS`) before an opportunistic sweep discards anything unclaimed — encrypted at rest under the same SQLCipher database as everything else the relay stores, never a weaker guarantee, but worth noting as new attack surface (however small) a reviewer should know exists.

This project is published for research, academic review, and engineering demonstration purposes only.

---

## Components

| Directory | Description |
|-----------|-------------|
| [`/protocol`](protocol/) | Rust: libsignal-protocol wrapper (X3DH, Double Ratchet, key gen), sealed sender, Sphinx mix-network packet build/unwrap (`mixnet`), transport abstraction, time-bound + read-triggered + combined self-destruct (`self_destruct`, `clock_guard`, `secure_memory`), session-burn, blinded dead-drop addressing (`dead_drop`, Sub-Phase 4C), out-of-band trust verification (`trust`, Sub-Phase 4.5D), native plaintext buffer FFI (`plaintext_ffi`, Sub-Phase 4.5C) |
| [`/server`](server/) | Rust/Axum: dumb-pipe relay server (store-and-forward), SQLCipher persistence, sealed-sender certificate authority |
| [`/mixnode`](mixnode/) | Rust/Axum: mix-network node daemon — Sphinx forwarding, per-hop mixing delay, drop-cover traffic (Sub-Phase 2B) |
| [`/gateway`](gateway/) | Rust/Axum: typed, versioned REST API gateway in front of `parda-relay` (Sub-Phase 3D) |
| [`/client-store`](client-store/) | Rust: client-side encrypted local message store (SQLCipher), structurally excludes self-destructing messages (Sub-Phase 3D) |
| [`/cli`](cli/) | Rust: CLI prototype exercising the full send/receive/self-destruct/burn flow end-to-end (Sub-Phase 3D) |
| [`/mesh`](mesh/) | Rust: offline mesh dead-drop — BLE proximity transport (`radio`, real backend on Linux/`bluer` + simulated), DTN store-and-forward relay agent (`relay`, `bundle`), `MeshTransport`/`HybridTransport`, multi-node simulation harness (`sim`) (Phase 4) |
| [`/mobile-bridge`](mobile-bridge/) | Rust: Android JNI bridge — `AndroidMeshRadio` (BLE, Sub-Phase 4.5B) and the native plaintext-handle exports (Sub-Phase 4.5C). Builds as a `cdylib` via `cargo-ndk` |
| [`/tls`](tls/) | Rust: shared native rustls TLS termination for the relay, mix node, and gateway (Sub-Phase 4.5E) |
| [`/mobile`](mobile/) | Flutter: cross-platform client with Android Keystore integration; Android plugins for Signal, mesh, and plaintext handles. iOS bridge present but never compiled |
| [`/docs`](docs/) | Architecture decisions, threat model, per-sub-phase design notes |

See [`docs/phase1-architecture.md`](docs/phase1-architecture.md) for stack decisions and tradeoffs.

---

## Setup & Installation

### Prerequisites

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update stable

# Flutter SDK (for the Android client)
# See: https://flutter.dev/docs/get-started/install
```

Two build prerequisites are easy to trip over and are documented rather
than left to be discovered:

- **`parda-relay`, `parda-client-store`, and `parda-cli` need a complete
  Perl** for the vendored SQLCipher/OpenSSL build (`docs/phase1-architecture.md`
  §11). Git-for-Windows' minimal Perl is not enough; Strawberry Perl works.
- **The Android client needs `cargo-ndk`** and the Android Rust targets:
  ```bash
  cargo install cargo-ndk
  rustup target add aarch64-linux-android x86_64-linux-android
  ```

### Build and test the Rust workspace

```bash
cargo build --workspace
cargo test  --workspace          # 170 tests
```

### Run the Android client end-to-end

This is the path that has actually been exercised on hardware (a Pixel 8,
Android 17) — see Status & Limitations for exactly what that did and did
not prove.

**1. Start a relay.**

```bash
PARDA_DB_KEY=$(openssl rand -hex 32) \
PARDA_DB_PATH=./parda-relay.sqlite3 \
PARDA_BIND=127.0.0.1:8080 \
cargo run -p parda-relay
```

**2. Make it reachable from the phone.** `adb reverse` maps the device's
own loopback to the host's, so the app's default relay URL works
unchanged over USB:

```bash
adb reverse tcp:8080 tcp:8080
```

On an emulator instead of a physical device, skip this and pick the
"Android emulator" preset in the app's Settings (`10.0.2.2`).

**3. Build and install the app.**

```bash
cargo ndk -t arm64-v8a -o mobile/android/app/src/main/jniLibs \
  build -p parda-mobile-bridge
cd mobile && flutter build apk --debug && flutter install
```

**4. Enroll.** Open the app, pick a user ID, confirm the relay address,
and tap *Generate keys & enroll*. The home screen's status bar should
read **Relay online**.

**5. Give yourself someone to talk to.** Messaging needs a second party.
`parda-cli peer` is a real one — it generates a Signal identity,
publishes a prekey bundle over HTTP, and decrypts what it receives:

```bash
cargo run -p parda-cli -- peer \
  --relay-url http://127.0.0.1:8080 --user-id bob --echo
```

Then tap **New chat** in the app, enter `bob`, and send a message. With
`--echo` the peer replies, so both directions are exercised. The peer's
identity is regenerated on every run and is not persisted — restarting it
invalidates the app's existing session with it.

**Optional — mesh mode.** Settings → *Mesh mode* requests the Bluetooth
permissions and starts advertising. `adb logcat -s parda` shows the Rust
side's own log output, and `adb shell dumpsys bluetooth_manager` will
list `com.parda.app` as an active advertiser once it is running.

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
