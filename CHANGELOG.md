# Changelog

All notable changes to **PARDA** (Privacy-Assured Resilient Defense Architecture) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added — Sub-Phase 2A (Sealed Sender + Persistence)

#### Protocol Layer (`/protocol`)
- `envelope` module: `version: u8` field on `MessageEnvelope` (`ENVELOPE_VERSION_V1`, `ENVELOPE_VERSION_V2`); `MessageEnvelope::validate_version()` rejects unsupported versions and inconsistent sealed-sender flags via `PardaError::UnsupportedEnvelopeVersion` / `PardaError::MalformedSealedSender` instead of misinterpreting bytes; old JSON without a `version` field deserialises as `ENVELOPE_VERSION_V1` via `#[serde(default)]`
- `envelope` module: new `EnvelopeType::SealedSender` variant
- `sealed_sender` module (new): `TrustRoot` and `CertificateAuthority`, wrapping `libsignal-protocol`'s own sealed-sender implementation (`SenderCertificate`, `ServerCertificate`, `sealed_sender_encrypt`/`sealed_sender_decrypt` — Signal's published sealed-sender design, no custom crypto)
- `session` module: `SessionManager::encrypt_sealed` / `decrypt_sealed`, alongside the existing `encrypt`/`decrypt`; `decrypt()` now calls `validate_version()` first and explicitly refuses `SealedSender` envelopes rather than mis-parsing them
- `error` module: `PardaError::UnsupportedEnvelopeVersion`, `PardaError::MalformedSealedSender`, `PardaError::SealedSenderAuth`
- `lib.rs`: re-exports `DeviceId`, `PublicKey`, `SenderCertificate`, `ServerCertificate` so downstream crates (the relay) don't need a direct `libsignal-protocol` dependency

#### Tests (`/protocol/tests`)
- `sealed_sender_tests.rs` — 5 tests: round-trip authentication + wire-secrecy check, and three adversarial cases (wrong trust root, expired certificate, certificate forged by an untrusted CA impersonating a real `sender_uuid`), plus a test that `decrypt()` refuses a sealed-sender envelope
- `crypto_tests.rs`: 3 new tests for envelope versioning (`test_envelope_missing_version_defaults_to_v1`, `test_envelope_future_version_rejected_explicitly`); existing `test_envelope_json_roundtrip` updated for the `version` field

#### Relay Server (`/server`)
- `store` module: rewritten from an in-memory `HashMap` store to a SQLCipher-backed store (`rusqlite`, `bundled-sqlcipher-vendored-openssl`) — encrypted at rest, survives process restart, schema migrations tracked via `PRAGMA user_version`. `PARDA_DB_KEY` is required at startup (no default/silent fallback); `PARDA_DB_PATH` defaults to `parda-relay.sqlite3`. `RelayStore::open_ephemeral()` added for tests (in-memory, fixed test key)
- New endpoints: `POST /v1/certs/{user_id}` (issue a sealed-sender `SenderCertificate`), `GET /v1/certs/trust-root` (fetch the trust root public key) — same Trust-On-First-Use posture as the existing `/v1/keys/{user_id}` prekey bundle endpoints; no account authentication exists yet
- `routes.rs`: `submit_message` no longer logs `sender_id`; every handler audited to never read or emit a sender identity for sealed-sender envelopes
- `main.rs` / `lib.rs`: router construction extracted into `parda_relay::app()` (new `src/lib.rs`) so integration tests can build the same router without a real TCP bind
- `models.rs`: `IssueSenderCertRequest`, `SenderCertificateResponse`, `TrustRootResponse`

#### Tests (`/server/tests`, new)
- `sealed_sender_relay_tests.rs::test_malicious_relay_cannot_recover_sender_identity` — adversarial harness with full access to the real relay's captured trace output and live store contents; sends a corpus of 12 distinct sealed senders and asserts none is recoverable from either surface
- `persistence_tests.rs` — 4 tests: data survives a simulated restart, wrong `PARDA_DB_KEY` fails loudly rather than returning garbage, the raw database file on disk contains no plaintext marker/recipient string (proves encryption at rest rather than assuming it from the `PRAGMA key` call), reopening (re-running migrations against) an existing database preserves data

#### CI
- `.github/workflows/ci.yml` (new): `cargo build` + `cargo test --workspace` on push/PR to `main`, matrixed over `ubuntu-latest` and `windows-latest` — closes the "GitHub Actions CI pipeline" item planned but never delivered for 0.1.0

#### Documentation
- `docs/THREAT_MODEL.md`: finalized for Phase 1 + Sub-Phase 2A (was draft v0.0.1); added §3.5 (curious/malicious relay operator — sealed sender's actual guarantee and its IP-address caveat) and §3.6 (Sub-Phase 2B mix-network adversary capability boundaries — design target for the not-yet-built mix network, so future batching parameters are threat-model outputs rather than free variables); §5 status table now cites the specific test backing every ✅
- `README.md`: Status & Limitations table updated — every ✅ now traceable to a test; added the sealed-sender-hides-identity-not-IP caveat and the CA trust-assumption caveat

### Fixed — Phase 1 baseline (discovered while building Sub-Phase 2A)

The existing Phase 1 code had never actually been compiled against its own pinned `libsignal-protocol` tag (`v0.66.0`) or run through `cargo test` — `Cargo.lock` was never committed, so this had silently drifted. Fixed to establish a real, verified baseline before adding Phase 2 code on top:

- `protocol/Cargo.toml`: added the missing `reqwest` dependency (`transport.rs` used it but it was never declared)
- `protocol/src/store.rs`: `InMemorySignalProtocolStore` now implements `KyberPreKeyStore` (required by the pinned libsignal version's `message_decrypt` signature, unused — no PQXDH); rewritten to hold its state behind `Rc<RefCell<..>>` so it can be cheaply cloned per simultaneous trait-object parameter — passing `&mut self.store` twice to one function call (the original shape) is not valid Rust, since it requires two live exclusive borrows of the same place at once
- `protocol/src/identity.rs`, `protocol/tests/crypto_tests.rs`: updated for `libsignal-protocol` v0.66.0 API drift (`GenericSignedPreKey` trait import required for `SignedPreKeyRecord` methods; `Timestamp` type instead of raw `u64`; `verify_signature` returns `bool`, not `Result<bool, _>`)
- `protocol/tests/crypto_tests.rs::test_multi_message_ratchet_advancement`: corrected an incorrect assumption that Alice's outgoing messages become `Ratchet`-typed after the first message regardless of whether Bob has replied — per the Signal Protocol spec (and libsignal's implementation), a session keeps emitting `PreKeySignalMessage`s until the sender processes a reply, so the test now has Bob ack once to exercise the transition it was meant to test
- `server/Cargo.toml`: `axum-test = "0.4"` doesn't exist on crates.io (yanked/never published at that version) — bumped to `"14"`, the version compatible with `axum = "0.7"`
- `server/src/lib.rs` (route construction, extracted from `main.rs`): the router registered `/v1/messages/:user_id` (GET) and `/v1/messages/:recipient_id` (POST) as separate path templates for the same route — axum 0.7's router rejects two method registrations at the same path with different parameter names. Unified to `:user_id` on both

### Added — Phase 1 (Core E2EE Messaging)

#### Architecture
- `docs/phase1-architecture.md` — full architecture decision record covering Signal Protocol library selection, Rust vs. alternatives, Flutter platform channel rationale, key storage approach, relay server design, and explicit Phase 2-4 extension points

#### Protocol Layer (`/protocol`)
- Rust crate `parda-protocol` wrapping `libsignal-protocol` (Signal Foundation, pinned git dependency)
- `identity` module: `LocalIdentity` struct for one-shot key generation — identity key pair, signed prekey (Ed25519-signed), 100 one-time Curve25519 prekeys
- `store` module: `InMemorySignalProtocolStore` implementing all four libsignal storage traits (`SessionStore`, `PreKeyStore`, `SignedPreKeyStore`, `IdentityKeyStore`) for test use; `PardaKeyStore` marker trait for production hardware-backed stores
- `session` module: `SessionManager` wrapping `process_prekey_bundle` (X3DH), `message_encrypt` and `message_decrypt` (Double Ratchet)
- `envelope` module: `MessageEnvelope` wire format with Phase 2 stubs (`sealed_sender`, `routing_hint`) and Phase 3 stub (`self_destruct_at`)
- `transport` module: `TransportLayer` async trait; `DirectTransport` (Phase 1 HTTP implementation); `MixTransport` unimplemented stub (Phase 2)
- Workspace `Cargo.toml` with shared dependency versions for `protocol` and `server` crates

#### Tests (`/protocol/tests`)
- `crypto_tests.rs` — 7 unit / integration tests:
  - `test_identity_key_generation` — key pair validity and uniqueness
  - `test_signed_prekey_signature_is_valid` — Ed25519 signature verification
  - `test_prekey_bundle_construction` — PreKeyBundle registration ID check
  - `test_x3dh_session_initiation` — Alice initiates with Bob's prekey bundle
  - `test_double_ratchet_encrypt_decrypt_roundtrip` — full PreKey → decrypt flow
  - `test_multi_message_ratchet_advancement` — 5 messages, ratchet advancement, envelope type checking
  - `test_forward_secrecy_stale_ciphertext_rejected` — replay of consumed PreKey envelope rejected
  - `test_envelope_json_roundtrip` — serialise / deserialise envelope with base64 ciphertext

#### Relay Server (`/server`)
- Rust crate `parda-relay` using Axum 0.7 + Tokio async runtime
- REST API v1: `POST /v1/keys/{user_id}`, `GET /v1/keys/{user_id}`, `POST /v1/messages/{recipient_id}`, `GET /v1/messages/{user_id}`, `DELETE /v1/messages/{user_id}/{msg_id}`, `GET /health`
- `RelayStore`: async `RwLock`-protected in-memory prekey bundle map and per-user message queues
- Server inspects zero ciphertext content — routes only on `recipient_id` path parameter
- `TraceLayer` + `CorsLayer` middleware; configurable bind address via `PARDA_BIND` env var

#### Mobile Client (`/mobile`)
- Flutter project targeting Android ≥ 8.0 (API 26) and iOS ≥ 14
- `SignalBridge` (Dart): MethodChannel bridge to native crypto — `generateIdentity`, `processPreKeyBundle`, `encryptMessage`, `decryptMessage`, `hasSession`
- `SignalPlugin.kt` (Kotlin): Android plugin wrapping `libsignal-android` — X3DH session building, AES-256 + HMAC encrypt/decrypt, Android Keystore key binding
- `SessionService`: enrollment flow, X3DH session initiation, message send/receive, 5-second relay polling
- `ApiService`: typed HTTP client for all relay API endpoints
- `HomeScreen`: conversations list with dark military aesthetic, empty state, new conversation dialog
- `ChatScreen`: gradient chat bubbles with message status icons (sending/sent/delivered/failed), security info bottom sheet showing protocol details and prototype disclaimer
- `_OnboardingScreen`: first-run identity generation with hardware key generation callout
- Phase 2-4 feature flags defined as `false` in `AppConfig`

#### Documentation
- `README.md`: updated Status & Limitations with Phase 1 delivery table, per-phase feature matrix, additional Phase 1 limitations (metadata visibility, in-memory store, no TLS), Phase 1 Components directory table

---

## [0.1.0] — Unreleased (Target: Phase 1 Complete)

> First working end-to-end encrypted messaging milestone.
> This release will mark the completion of the core cryptographic layer (Phase 1).

### Planned

- `libsignal-client` integration: X3DH key exchange and Double Ratchet session establishment
- Per-message ephemeral key derivation with forward secrecy
- Zeroize-on-expiry self-destruct: time-bound key deletion backed by `zeroize`/`memzero`
- SQLCipher encrypted local message store
- Rust CLI prototype: send and receive E2EE messages over a local loopback transport
- Unit test suite for cryptographic primitives (`cargo test`)
- GitHub Actions CI pipeline (build + test on push)
- Finalized `LICENSE` file
- Published `CONTRIBUTING.md` with CLA

---

[Unreleased]: https://github.com/your-org/parda/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-org/parda/releases/tag/v0.1.0
