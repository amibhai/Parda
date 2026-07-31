# PARDA Phase 1 — Architecture Decision Record

**Status:** Accepted  
**Date:** 2026-06-30  
**Last reviewed:** 2026-07-01  
**Phase:** 1 — Core End-to-End Encrypted Messaging  
**Author:** PARDA Engineering

---

## 1. Context & Scope

Phase 1 establishes the cryptographic foundation of PARDA: authenticated
key exchange, a self-healing Double Ratchet session, local key storage backed
by hardware security, and a minimal relay server that sees only opaque
ciphertext. Later phases layer mix-network metadata resistance, cryptographic
self-destruct, and offline mesh dead-drop delivery on top of this foundation.

This document records every non-trivial decision made for Phase 1, along with
the alternatives considered and the explicit reasons they were rejected.

---

## 2. Protocol Layer

### Decision: Signal Protocol (X3DH + Double Ratchet) via `libsignal-protocol`

**Library chosen:** `libsignal-protocol` Rust crate from the Signal Foundation
monorepo (`github.com/signalapp/libsignal`).

**Rationale:**
- The Signal Protocol is the only widely-deployed, peer-reviewed, formally
  verified ratchet-based messaging protocol with published security proofs
  (Cohn-Gordon et al., 2017; Alwen et al., 2019).
- `libsignal-protocol` is the Signal Foundation's own implementation — the
  exact same code used in Signal Messenger. It has received multiple
  third-party security audits.
- Using the upstream crate (rather than a community re-implementation) means
  security fixes automatically flow in via dependency updates.
- The Rust implementation gives us memory safety and prevents the class of
  buffer-overflow / use-after-free bugs that have plagued C signal-protocol
  ports.

**Alternatives considered:**

| Alternative | Reason rejected |
|-------------|-----------------|
| Hand-rolled X3DH/DR using `x25519-dalek` + `hkdf` | Assembling audited primitives into an unaudited protocol breaks the no-custom-crypto constraint. Even correct assembly of good primitives can introduce protocol-level vulnerabilities. |
| `double-ratchet` crate (crates.io) | Community crate, no third-party audit, low maintenance activity. |
| Noise Protocol Framework (`snow` crate) | Noise-XX provides mutual auth but lacks the asynchronous prekey model needed for offline message delivery. Would require a custom pre-key layer on top, re-introducing custom protocol assembly. |
| Matrix Olm/Megolm | Based on Signal Protocol but has known deviations from the reference spec; received fewer audits than the Signal Foundation's own library. |

**Constraint flag:** `libsignal-protocol` is not published on crates.io. It is
consumed as a git dependency from the Signal Foundation monorepo. This means:
- Cargo resolves the dependency at build time from GitHub (requires internet).
- The exact commit/tag must be pinned in `Cargo.lock` — **never float the
  libsignal dependency**.
- Building requires: Rust ≥ 1.75, clang/LLVM (for the C bridge layer on
  some targets), and on Windows: MSVC Build Tools 2022.

---

## 3. Language & Runtime

### Decision: Rust for protocol layer and relay server

**Rationale:**
- Memory safety without a garbage collector is essential for cryptographic
  code — no risk of key material being copied to GC-scanned heap.
- `zeroize` crate enables guaranteed overwriting of sensitive memory before
  deallocation — a property that is difficult to guarantee in GC languages.
- The type system catches misuse of cryptographic types at compile time
  (e.g., cannot accidentally pass a private key where a public key is expected).
- `tokio` async runtime handles concurrent session management without threads,
  keeping server resource usage low.
- A single language for both the protocol library and the relay server means
  shared `models` types can be compiled into both without FFI.

**Alternatives considered:**

| Alternative | Reason rejected |
|-------------|-----------------|
| Go for relay server | Garbage collector cannot guarantee key material zeroing. No equivalent of `zeroize`. |
| TypeScript / Node.js | Signal Foundation publishes `@signalapp/libsignal-client` npm package which would simplify integration, but GC and weak memory guarantees rule it out for a security prototype. |

---

## 4. Mobile Client

### Decision: Flutter + Platform Channels + libsignal native bindings

**Rationale for Flutter:**
- Single codebase for Android and iOS reduces maintenance burden during
  research prototype phase.
- Dart is memory-managed but all cryptographic operations are delegated to
  native platform code via Method Channels — the GC never touches key material.
- Flutter's widget toolkit allows polished UI without React Native's bridge
  overhead for renders.

**Rationale for Platform Channels (not Flutter FFI to Rust):**
- Android Keystore and iOS Secure Enclave APIs are Java/Kotlin and Swift/Obj-C
  APIs respectively. Bridging them to Rust via FFI would require a non-trivial
  JNI layer on Android and a Swift-C bridge on iOS.
- The Signal Foundation already ships `libsignal-android` (Java/Kotlin) and
  `libsignal-swift` (Swift) as official pre-built artifacts. Using these means
  the mobile client runs the same audited binary as Signal Messenger.
- Platform channels cleanly separate the Flutter UI layer from all crypto
  operations — matching our layering requirement.

**Phase 2 note:** If the Rust protocol crate needs to run on-device (e.g., for
mix-routing logic), a `flutter_rust_bridge` integration can replace or
augment the current platform channel approach without changing the Flutter UI
layer.

**Alternatives considered:**

| Alternative | Reason rejected |
|-------------|-----------------|
| React Native + `@signalapp/libsignal-client` | More direct libsignal JS binding, but weaker memory guarantees, less ergonomic platform integration for Keystore/Secure Enclave. |
| Kotlin Multiplatform (KMM) | Excellent libsignal integration, but requires separate UI implementations per platform — too much overhead for a Phase 1 prototype. |
| Native Android-only (Kotlin) | Excludes iOS entirely; acceptable later but not for Phase 1. |

---

## 5. Key Storage

### Decision: Hardware-Backed Secure Storage via Platform APIs

| Platform | Mechanism |
|----------|-----------|
| Android | Android Keystore System (hardware-backed, StrongBox if available) |
| iOS | iOS Secure Enclave (T1/T2 chip, `kSecAttrTokenIDSecureEnclave`) |
| Development/Test | In-memory `InMemorySignalProtocolStore` (never in production) |

**Properties guaranteed by hardware-backed storage:**
- Private key bytes never exist in accessible memory — operations are performed
  *inside* the secure element.
- Keys are bound to the device; cannot be exported or migrated.
- Operations require user authentication (biometric / PIN) where configured.

**Constraint:** The in-memory test store used in Rust unit tests is explicitly
marked `#[cfg(test)]` and has compilation guards preventing use outside test
contexts. Any future persistent store implementation must pass a security review
before being merged.

---

## 6. Relay Server Design

### Decision: Dumb-Pipe Store-and-Forward via REST

The relay server is deliberately minimal:
- No account management or authentication in Phase 1 (added in Phase 2 with
  sealed-sender envelopes).
- Accepts opaque `MessageEnvelope` JSON blobs; stores them in an in-memory
  queue keyed by recipient ID.
- Serves prekey bundles to senders (Bob uploads; Alice fetches).
- **Zero ability to read message content** — ciphertext is never decrypted
  server-side.

**API surface (v1):**

```
POST   /v1/keys/{user_id}                  Upload prekey bundle
GET    /v1/keys/{user_id}                  Fetch prekey bundle
POST   /v1/messages/{recipient_id}         Submit encrypted envelope
GET    /v1/messages/{user_id}              Fetch pending messages
DELETE /v1/messages/{user_id}/{msg_id}     Acknowledge & delete message
```

**Phase 1 limitations (explicit):**
- In-memory storage: all messages lost on server restart (Phase 2: SQLite / PostgreSQL).
- No TLS termination in the server binary itself (Phase 1: use a reverse proxy;
  Phase 2: integrated mTLS via rustls).
- No rate limiting, no DDoS protection.
- No sealed-sender: server can see sender → recipient mapping (Phase 2).

---

## 7. Layer Separation & Extension Points

The layered architecture is enforced by module boundaries:

```
┌─────────────────────────────────────────┐
│           Flutter UI Layer              │  mobile/lib/screens/
├─────────────────────────────────────────┤
│         Session Service Layer           │  mobile/lib/services/session_service.dart
├─────────────────────────────────────────┤
│  Transport Layer (Phase 2 stub)         │  protocol/src/transport.rs
│  DirectTransport (Phase 1)              │   └─ impl TransportLayer
│  MixTransport     (Phase 2, TODO)       │   └─ TODO stub
├─────────────────────────────────────────┤
│  Crypto / Protocol Layer                │  protocol/src/
│  X3DH + Double Ratchet (libsignal)     │
├─────────────────────────────────────────┤
│  Key Storage Layer                      │  protocol/src/store.rs (trait)
│  InMemoryStore (test)                   │   └─ impl for tests
│  HardwareStore  (prod, via MethodChn.)  │   └─ impl via platform channel
└─────────────────────────────────────────┘
```

**Extension stubs present in Phase 1 code:**
- `TransportLayer` trait — Phase 2 replaces `DirectTransport` with `MixTransport`.
- `MessageEnvelope::routing_hint` field — reserved for mix-node onion header
  (always `None` in Phase 1).
- `MessageEnvelope::self_destruct_at` field — reserved for Phase 3 self-destruct
  timestamp (always `None` in Phase 1).
- `sealed_sender: bool` flag on `MessageEnvelope` — Phase 2 activates this.

---

## 8. Build Prerequisites

### Rust (protocol + server)

```bash
rustup install stable          # >= 1.75
rustup target add aarch64-linux-android   # if building for Android
# Windows: MSVC Build Tools 2022 required (not MinGW)
```

**Additional prerequisites as of Sub-Phase 2A (§11):**
- `protoc` (Protocol Buffers compiler) — required by `libsignal-protocol`'s
  build script. `apt install protobuf-compiler` / `choco install protoc` /
  download from the [protobuf releases page](https://github.com/protocolbuffers/protobuf/releases).
- A complete Perl — required by `parda-relay`'s vendored SQLCipher/OpenSSL
  build. See §11 for the Windows-specific gotcha and fix.

### Flutter (mobile)

```bash
flutter --version              # >= 3.22 recommended
flutter doctor                 # verify dependencies
```

### Android

- Android Studio with NDK r26+
- `libsignal-android` AAR is fetched via Maven Central
- `minSdkVersion 26` (Android 8.0) required for StrongBox Keystore

### iOS

- Xcode 15+
- `libsignal-swift` via Swift Package Manager

---

## 9. Deferred to Later Phases

| Feature | Phase |
|---------|-------|
| Sealed-sender envelopes | 2 |
| Sphinx-packet mix-network routing | 2 |
| Cover traffic scheduler | 2 |
| Cryptographic self-destruct (time-bound key) | 3 |
| Secure memory wipe on expiry | 3 |
| BLE / Wi-Fi Direct mesh transport | 4 |
| DTN store-and-forward relay | 4 |
| Post-quantum key encapsulation (ML-KEM) | 5 |
| FIPS 140-3 module validation | Post-research |
| Formal security audit | Post-research |

---

## 10. Known Risks in Phase 1

1. **No sealed sender:** The relay server logs sender → recipient pairs. This is
   acceptable in Phase 1 (research prototype, no real users) but must be resolved
   before any operational evaluation.
2. **In-memory relay store:** All queued messages are lost on server crash. No
   durability guarantee.
3. **No server authentication:** Clients connect to the relay without verifying its
   identity (no certificate pinning in Phase 1). A MITM could inject prekey bundles.
   Mitigated by: manual out-of-band key verification (safety numbers equivalent).
4. **Windows Rust build complexity:** libsignal-protocol has native C extensions;
   building on Windows requires MSVC and correct PATH configuration.
5. **libsignal git dependency:** Floating the dependency (no pinned tag) risks
   upstream API breaks. `Cargo.lock` must be committed.
6. **One-time prekey exhaustion:** If Alice sends many sessions before Bob
   replenishes his one-time prekey pool, the relay returns bundles without a
   one-time prekey. This is safe per the X3DH spec but slightly weakens
   forward secrecy for that session. Phase 2 will add automatic pool
   replenishment logic to `SessionService`.

---

## 11. Sub-Phase 2A Addendum (Sealed Sender + Persistence)

**Status:** Accepted | **Date:** 2026-07-31

This ADR predates Sub-Phase 2A; the decisions below extend it rather than
revise the sections above (§1-10 remain an accurate record of what was
decided for Phase 1). Risks #1 and #2 in §10 are resolved as described here;
risk #3 is unchanged (sealed sender authenticates senders to recipients, not
clients to the relay — see `docs/THREAT_MODEL.md` §3.5).

**Sealed sender:** implemented by calling `libsignal-protocol`'s own
`sealed_sender_encrypt`/`sealed_sender_decrypt` and `SenderCertificate`/
`ServerCertificate` types directly (already vendored in the pinned
`v0.66.0` tag) rather than assembling anything from primitives — consistent
with the no-custom-crypto constraint in §2. `parda-relay` hosts the
certificate authority, at the same Trust-On-First-Use trust level Phase 1
already accepted for prekey bundle uploads (no new trust assumption
introduced, an existing one extended).

**Relay persistence:** `rusqlite` with the `bundled-sqlcipher-vendored-openssl`
feature — compiles SQLCipher and OpenSSL from source, so no system SQLCipher
or OpenSSL install is required on the build machine. This carries one real
build prerequisite worth flagging explicitly: **a complete, working Perl**
(OpenSSL's `Configure` step needs it). On Linux/macOS this is normally a
non-issue. On Windows, the Perl bundled with some Git-for-Windows /
lightweight MSYS installs is missing CPAN modules OpenSSL's `Configure`
needs (`Locale::Maketext::Simple` was the specific gap hit during Sub-Phase
2A development) — install
[Strawberry Perl](https://strawberryperl.com) (portable ZIP is sufficient)
and ensure it's on `PATH` ahead of any other `perl`. GitHub Actions'
`windows-latest` runner ships a working Perl already, so CI is unaffected;
this is a local Windows dev-machine setup note only. Added to §8 build
prerequisites below.

**Envelope versioning:** added ahead of any further wire-format changes
(§9's Sphinx routing-hint work in Sub-Phase 2B will be the next one), per
the explicit requirement that version mismatches fail loud rather than
silently misinterpret bytes.

---

## 12. Sub-Phase 2B Addendum (Sphinx Mix-Network Routing)

**Status:** Accepted | **Date:** 2026-07-31

### Decision: `sphinx-packet` crate for Sphinx packet construction/unwrap

**Library chosen:** `sphinx-packet` (crates.io, v0.7.0, Apache-2.0,
`github.com/nymtech/sphinx`), maintained by Nym Technologies and used in
production by the Nym mixnet.

**Rationale:**
- Implements the packet format from Danezis & Goldberg, "Sphinx: A
  Compact and Provably Secure Mix Format" (IEEE S&P 2009) — the same
  no-custom-crypto constraint from §2 applies here: assembling onion
  encryption from primitives (AES/ChaCha20 + HMAC by hand) would risk
  reintroducing protocol-level bugs an existing, production-exercised
  implementation has already had scrutiny against.
- Ships its own Poisson/exponential per-hop delay generator
  (`header::delays::generate_from_average_duration`), which
  `protocol/src/mixnet.rs` uses directly rather than reimplementing —
  see §2's reasoning applied consistently.
- Not published by the Signal Foundation (unlike `libsignal-protocol`),
  so this is a materially different trust chain from Phase 1's crypto
  dependency — recorded here explicitly rather than left implicit.

**Alternatives considered:**

| Alternative | Reason rejected |
|-------------|-----------------|
| Hand-rolled onion encryption (AES/ChaCha20 + HMAC layers) | Breaks the no-custom-crypto constraint (§2); mix-format bugs (e.g. malleable routing info, tagging attacks) are exactly the class of subtle protocol error published, audited formats exist to avoid. |
| `sphinxcrypto` crate (crates.io) | A "concrete parameterization of the Sphinx cryptographic packet format," but with a smaller install base and no equivalent production deployment backing it at the time of this decision. |
| Building mix routing directly into `parda-relay` | Rejected per this sub-phase's explicit requirement to keep routing/batching architecturally separate from store-and-forward, even though both may co-locate in a dev deployment — see `mixnode/Cargo.toml`. |

### Decision: sender-sampled, node-honored per-hop delay (not node-sampled)

Per-hop mixing delay is sampled once by the sender (`mixnet::build_packet`)
and embedded in the Sphinx header; each node (`mixnet::process_packet`)
honors the delay it's handed rather than sampling its own. This is the
actual Sphinx/Loopix design, not a PARDA simplification — a node that
sampled its own delay could have that sampling process influenced,
observed, or fingerprinted in ways the sender-committed approach avoids.
Continuous-time (per-packet) delay was chosen over a batch-and-flush
scheme because batching reintroduces a "which packets shared a batch"
correlation signal that Loopix's design specifically avoids — see
`mixnode/src/mixing.rs` module docs.

### Decision: mix nodes carry no topology, only an optional peer list

A mix node needs only its own keypair to forward traffic — the next
hop's address is recovered directly from what it decrypts out of the
Sphinx packet header (`protocol/src/mixnet.rs`, "Address encoding"). Only
the client, which picks the *initial* path, needs the full
`MixTopology`. This keeps a node's configuration surface small and
avoids giving every node in the network a copy of the full topology
(which would be a bigger information-leakage surface if any single node
were compromised). The tradeoff: cover-traffic emission
(`mixnode/src/cover_traffic.rs`) *does* need a small peer list
(`MIXNODE_PEERS`) to build validly-encrypted cover packets — a node with
no configured peers simply emits no cover traffic, logged as a
limitation rather than silently degraded.

### Known limitation carried forward

`MixTopology` is a static, trust-on-first-use configured list — no
decentralized directory authority, no freshness or revocation mechanism.
Same trust posture already accepted for prekey bundle upload (§10 risk
#3) and sealed-sender certificate issuance (§11). A production deployment
needs a signed, Byzantine-fault-tolerant directory service; explicitly
out of scope here — see `docs/THREAT_MODEL.md` §3.6 and §4.

### Extension stubs resolved

- `TransportLayer::MixTransport` (§7, previously a `unimplemented!()`
  stub) is now a real implementation — see `protocol/src/transport.rs`.
- `MessageEnvelope::routing_hint` (§7) remains unused/`None`. The design
  wraps the *entire serialised envelope* as the Sphinx packet payload
  rather than attaching a routing header to the envelope struct itself —
  see `protocol/src/envelope.rs` module docs for why this isn't an
  oversight.
