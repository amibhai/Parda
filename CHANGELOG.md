# Changelog

All notable changes to **PARDA** (Privacy-Assured Resilient Defense Architecture) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added — Sub-Phase 3D (Application Layer: Session-Burn, Client Store, CLI, REST Gateway)

Phase 3 (cryptographic self-destruct) is complete through this sub-phase.

#### Protocol Layer (`/protocol`)
- `store::InMemorySignalProtocolStore::burn_session` / `session::SessionManager::burn_conversation` (new): "burn this conversation" — removes session and trusted-identity state for a peer. Documented explicitly, everywhere the function appears, as a **materially weaker guarantee than message-level self-destruct**: `libsignal-protocol` v0.66.0's `PrivateKey` is a non-zeroizing `Copy` type (verified by reading the pinned tag's source), so byte-level erasure of session key material can't be proven the way `self_destruct::erase` proves it, without forking libsignal — the same no-custom-crypto tradeoff already declined once for the KDF (Sub-Phase 3A design note §1)
- `envelope::MessageEnvelope::read_triggered_destruct: bool` (new, `#[serde(default)]`, additive): `self_destruct_at` alone can't express "destroy on read" (no fixed deadline) — needed so `parda-client-store`'s write path can correctly exclude *both* destruct modes, not just time-bound. `MessageEnvelope::with_read_triggered_destruct()` builder added to match `with_self_destruct()`
- **Bug fix, found by actually running the new CLI**: `transport::{DirectTransport, MixTransport}::receive` deserialized the relay's `GET /v1/messages/{id}` response as a bare `Vec<MessageEnvelope>`; the relay has always returned `{"messages": [...]}`. Latent since Phase 1 — no existing test ever called `receive()` against a live relay. Fixed with a `FetchMessagesResponse` deserialization target matching the relay's actual shape

#### New crate `/client-store` (`parda-client-store`)
- `LocalMessageStore`: SQLCipher-backed client-side message history, mirroring `server/src/store.rs`'s proven encryption-at-rest pattern. `store_message` refuses — before any SQL runs, never a partial write — any envelope with `self_destruct_at` set or `read_triggered_destruct = true`. `history_for`, `delete_history_for` (for pairing with session-burn), `total_message_count`
- 7 tests, all passing: ordinary round-trip, both destruct-mode refusals, no-partial-write-on-refusal, per-peer scoping (read and delete), ordering

#### New crate `/gateway` (`parda-gateway`)
- Typed, versioned (`/api/v1/...`) REST gateway in front of `parda-relay`, reached over real HTTP (no crate dependency on `parda-relay`, so no vendored-SQLCipher build requirement for this crate specifically). Message routes forward request bodies as raw, unparsed `Bytes` — the strongest version of "never touch ciphertext," no intermediate typed value exists to log or inspect even by accident
- 3 tests: ciphertext passes through bit-identical, prekey bundle round-trips, unreachable relay surfaces as a clear 502 rather than a silent empty success

#### New crate `/cli` (`parda-cli`)
- `parda-cli demo [--expire-secs N | --read-once] [--relay-url URL]`: real X3DH handshake, real HTTP send/receive via `DirectTransport` against either a built-in stub relay or a real `parda-relay`, either self-destruct mode wrapped and demonstrated live (including the second-read/post-expiry failure), non-destructing messages persisted to the encrypted local store, then session-burn — actually run end-to-end for all three modes (plain, `--expire-secs`, `--read-once`) plus the mutually-exclusive-flags rejection, not just compiled

#### Build environment
- Resolved the `docs/phase1-architecture.md` §11 Perl gap for this session by installing a portable Strawberry Perl. `parda-client-store`, `parda-relay`, and `parda-mixnode`'s relay dev-dependency all compiled clean on the first try once unblocked — no logic bugs found in any of them by this fix; `parda-cli` needed two missing dependency lines added

#### Documentation
- `docs/phase3-3a-self-destruct-design.md` §12: session-burn's honest scope decision, the SQLCipher store's wire-format prerequisite, the gateway's architecture rationale, and the full Perl-gap/CLI-bug account
- `docs/THREAT_MODEL.md`, `README.md`: Phase 3 marked complete through 3D, with new limitations for the session-burn guarantee gap, the still-unverified mobile Kotlin fix, and the still-missing restart-survival story for pending self-destructing messages

### Added — Sub-Phase 3C (Cold-Boot / Swap / Forensic Recovery Hardening)

#### Protocol Layer (`/protocol`)
- `secure_memory` module (new): cross-platform `mlock`/`munlock` (Unix, `libc`) and `VirtualLock`/`VirtualUnlock` (Windows, `windows-sys`) — raw OS syscall FFI, not a crypto primitive. `locked_byte_count()` reads `/proc/self/status`'s `VmLck` on Linux so callers can verify a lock actually took effect via OS accounting, not just a non-error return code. Failure (e.g. `RLIMIT_MEMLOCK` in constrained containers) is logged and degrades swap-avoidance without breaking correctness
- `self_destruct::DerivedKey` changed from an inline `[u8; 32]` to a dedicated `Box<[u8; 32]>` allocation, locked in `DerivedKey::new` (immediately after HKDF writes into it) and unlocked in `Drop` after zeroizing — its own page(s), not shared with unrelated `Arc`/`Mutex` bookkeeping
- `Cargo.toml`: `libc` (unix-only target dependency), `windows-sys` with `Win32_System_Memory`/`Win32_Foundation` (windows-only target dependency)

#### Tests (`/protocol/src/secure_memory.rs`, `/protocol/tests/forensic_recovery_tests.rs`)
- `test_lock_increases_os_reported_locked_byte_count` / `test_locked_region_accounting_survives_memory_pressure` (Linux) — verify via `VmLck` accounting, including that the lock survives 256 MiB of genuine, touched memory pressure
- `forensic_recovery_tests.rs` — the sub-phase's actual deliverable per the brief's own framing: seals a distinctively-tagged plaintext under both destruct modes, confirms it's absent from scanned process memory pre-read and present post-read (sanity check on the scan technique), triggers destruction, simulates seizure, and asserts the plaintext is unrecoverable. Linux-only sub-tests do a literal `/proc/self/mem` dump; portable sub-tests check the public API refuses. Documents explicitly that "dump all accessible storage" finds nothing because `SelfDestructingMessage` has no serialization or file I/O at all — by absence of capability, not a runtime check

#### A real bug this sub-phase's own testing caught
Manually `ptr::drop_in_place`-ing a `DerivedKey` in a test, after it started owning a real heap allocation (the new `Box`), caused a double-free against the compiler's own end-of-scope drop for the same variable — `STATUS_HEAP_CORRUPTION` on the first run after the change. Fixed by testing the `zeroize()` method directly through a still-live, still-owned reference instead of manually driving `Drop` — the same category of "test the safe way zeroize's own test suite does" fix as Sub-Phase 3A's, applied to a new case

#### Mobile (`/mobile`)
- `SignalPlugin.kt`: `handleEncryptMessage`/`handleDecryptMessage` now clear their `ByteArray` plaintext copy (`java.util.Arrays.fill(plaintext, 0)`) in a `finally` block after use — a Sub-Phase 3C audit finding (decrypted plaintext crossed the MethodChannel boundary in an unmanaged JVM array with no clearing). **Not runtime-verified against a real Flutter build** — no Android/Flutter toolchain was available; see design note §9 for the reasoning this relies on
- No code changes to the Dart layer or iOS: audit findings only (Dart's `String`-based plaintext handling can't be provably erased regardless of native-layer discipline; no iOS native bridge exists to audit) — see design note §9

#### Documentation
- `docs/phase3-3a-self-destruct-design.md`: new §8 (swap-avoidance design + verification scope + forensic-recovery test), §9 (full mobile native-bridge audit write-up), updated §10/§11
- `docs/THREAT_MODEL.md` §3.4, §5: updated with Sub-Phase 3C's delivered scope, remaining gaps (hibernation, plaintext-buffer locking, Windows verification asymmetry, mobile Dart `String` limitation), and test citations
- `README.md`: Status table and seven new limitations documented (narrower-than-goal scope is the norm for this phase, not the exception)

### Added — Sub-Phase 3B (Read-Triggered Destruction)

#### Protocol Layer (`/protocol`)
- `self_destruct` module: `SelfDestructingMessage::seal_read_triggered` — no expiry timer; the key is erased on the first successful `open()`, inside the same held `Mutex` lock as the decrypt, before returning to the caller, so there is no window (concurrent or sequential) in which a second reader can find the key still live. `open()` is now mode-aware: time-bound messages behave exactly as in Sub-Phase 3A, read-triggered messages additionally erase-in-place on success
- Module docs restate the two modes' guarantees precisely per the brief's explicit requirement not to let them blur: time-bound = "gone by T regardless of read"; read-triggered = "gone after first read regardless of T," with no fallback timer

#### Tests (`/protocol/tests/self_destruct_tests.rs`)
- `test_time_bound_message_expires_even_if_never_read` / `test_read_triggered_message_has_no_timer_and_survives_until_read` — the two modes' guarantees, tested as the explicit symmetric pair the brief asked for
- `test_read_triggered_second_open_fails_closed_after_first_succeeds` — sequential double-read fails closed
- `test_read_triggered_concurrent_opens_only_one_succeeds` — the sub-phase's core deliverable: 32 tasks released simultaneously via a `tokio::sync::Barrier` race to open the same message; exactly one succeeds, deterministically (a mutex-structural guarantee, verified stable across repeated runs, not a timing-dependent one). Documented explicitly as the practical stand-in for "kill the process mid-render" for this in-memory-only primitive — see design note §5b for why a literal process-kill-and-restart test doesn't apply yet (nothing here persists across a real process exit; that's Sub-Phase 3D's job)

#### Documentation
- `docs/phase3-3a-self-destruct-design.md`: new §5b recording the atomicity design decision and the guarantee-separation table
- `docs/THREAT_MODEL.md` §3.4, §5: updated from "Sub-Phase 3A ... Sub-Phases 3B-3D not started" to include 3B's delivered scope and test citations
- `README.md`: Status table and two new limitations (read-triggered has no fallback timer by design; self-destructing messages don't yet survive an app restart while pending)

### Added — Sub-Phase 3A (Time-Bound Self-Destruct Key Derivation & Zeroize-on-Expiry)

#### Design
- `docs/phase3-3a-self-destruct-design.md` (new): the required pre-implementation design note, covering the KDF chain, why the key is derived from a fresh local secret rather than the (libsignal-inaccessible) Double-Ratchet message key, the monotonic-clock + rollback-watermark clock-trust mitigation and its documented limits, and — added during implementation — a real design flaw the memory-forensics test itself caught (see below)

#### Protocol Layer (`/protocol`)
- `self_destruct` module (new): `SelfDestructingMessage::seal`/`open`/`expire_now`/`open_with_clock_guard` — HKDF-SHA256 (RFC 5869, `hkdf` crate) derives a time-bound key from a fresh `OsRng` secret (never the Double-Ratchet key — see design note §1), ChaCha20-Poly1305 (RustCrypto) re-encrypts the recovered plaintext under it, and a monotonic-clock-anchored `tokio` timer erases the key at expiry. `DestructMode::{TimeBound, ReadTriggered}` exists now for HKDF domain separation ahead of Sub-Phase 3B; only `TimeBound` is implemented
- `clock_guard` module (new): `ClockWatermarkStore` trait + `InMemoryClockWatermarkStore`, `check_clock_integrity` — detects a wall-clock rollback across a process restart via a persisted watermark and fails closed rather than trusting a clock proven to have moved backward
- `error` module: `PardaError::SelfDestructExpired`, `PardaError::ClockRollbackDetected`, `PardaError::SelfDestructCrypto`
- `envelope` module: `MessageEnvelope::with_self_destruct()` sets the (advisory-only — see module docs on why it isn't the enforcement mechanism) `self_destruct_at` wire field
- `Cargo.toml`: `hkdf`, `chacha20poly1305`, `sha2` added; `tokio` moved from dev-dependencies to a real dependency (the expiry timer needs a runtime in the library itself, not just in tests)

#### Tests (`/protocol/src/self_destruct.rs`, `/protocol/tests`)
- Inline `#[cfg(test)]` unit tests (white-box, need private-field access): seal/open round-trip, `expire_now` fails closed, KDF domain separation by mode and by timestamp
- **Memory-forensics tests** — the sub-phase's actual deliverable: `test_erase_zeroizes_before_clearing_and_ends_up_gone` reads the key through a live, type-stable reference immediately before/after the explicit zeroize call (the same pattern the `zeroize` crate's own test suite uses); `test_zeroize_overwrites_key_bytes_on_ordinary_drop_too` proves `ZeroizeOnDrop` fires on the normal Rust drop path via `ptr::drop_in_place`; `linux_memory_scan_tests::test_key_bytes_absent_from_process_memory_after_expiry` (Linux-only, runs in the `ubuntu-latest` CI leg) scans all of `/proc/self/mem` for the key's exact bytes before and after erasure, with a sanity check that the scan technique can actually find data that's really there
- `protocol/tests/self_destruct_tests.rs` — black-box functional tests: real-timer expiry (not just `expire_now()`'s synchronous shortcut) fails closed; a not-yet-expired message stays readable; clock rollback is detected, reported, and permanently (not just for one call) expires the affected message without affecting other pending messages; `MessageEnvelope::with_self_destruct` sets the expected deadline

#### A real bug the memory-forensics test caught
The first implementation of key erasure did `*guard = None` directly on an `Option<DerivedKey>`. This does run `DerivedKey`'s `ZeroizeOnDrop` (a genuine volatile zero-write occurs), but the test — reading the same address via a pointer captured before the `Option` changed shape — intermittently found non-zero, pointer-shaped garbage instead of zeros. Root cause: once an `Option`'s variant changes, nothing guarantees the former payload bytes stay as whatever `Drop` last wrote, even inside a still-live allocation. Fixed by zeroizing explicitly while the value is still `Some`, then clearing to `None` as a separate step (`self_destruct::erase`) — and the test was rewritten to read through a live reference rather than a stale raw pointer, matching how the `zeroize` crate's own tests verify themselves. Recorded in the design note §5a and here because it's exactly the "the deletion function ran ≠ the plaintext is unrecoverable" distinction the brief asked to hold this phase to.

#### Documentation
- `docs/THREAT_MODEL.md`: §3.4 (Device Seizure Adversary) updated from "Phase 3, not started" to Sub-Phase 3A's actual, narrower delivered scope — what's proven (live-memory erasure) versus what remains open (swap/cold-boot, read-trigger, rooted-device/powered-off-device clock-trust gaps); §5 status table updated with test citations
- `README.md`: Status table rows for KDF, live-memory erasure, and clock-rollback detection moved to ✅ Sub-Phase 3A; five new limitations documented (DR-key substitution rationale, clock-trust gaps, swap/cold-boot not yet proven, pre-expiry memory dump is fundamentally undefendable); Components table updated

### Added — Sub-Phase 2B (Sphinx Mix-Network Routing)

#### New crate: `parda-mixnode` (`/mixnode`)
- Standalone mix-node daemon, architecturally separate from `parda-relay` per this sub-phase's explicit requirement (routing/batching is a distinct service from store-and-forward)
- `identity` module: X25519 node keypair loading (`MIXNODE_SECRET_KEY_HEX` env var, or ephemeral generation with a logged warning — no persistent/hardware-backed node identity yet)
- `mixing` module: honors the sender-embedded per-hop Sphinx delay, then forwards to the next hop or delivers to the relay — a detached `tokio::spawn` per packet, deliberately not a batch-and-flush queue (see module docs for why batching would reintroduce a correlation signal)
- `cover_traffic` module: Loopix-style "drop cover" traffic — exponentially-timed dummy Sphinx packets routed through `MIXNODE_PEERS`, tagged for silent discard at their final hop; a node with fewer than 3 configured peers emits none, logged as a limitation rather than silently degraded
- `routes`/`lib.rs`: `app(state)` Axum router (`GET /health`, `GET /mix/pubkey`, `POST /mix/packet`) mirroring `parda_relay::app(store)`'s test-without-TCP-bind pattern
- `main.rs`: daemon binary, env-configured (`MIXNODE_BIND`, `MIXNODE_RELAY_URL`, `MIXNODE_SECRET_KEY_HEX`, `MIXNODE_COVER_AVG_INTERVAL_MS`, `MIXNODE_PEERS`)

#### Protocol Layer (`/protocol`)
- `mixnet` module (new): Sphinx packet construction/unwrap built on the `sphinx-packet` crate (Nym Technologies, Apache-2.0, v0.7.0 — Danezis & Goldberg, IEEE S&P 2009) — no custom onion crypto. `MixTopology`/`MixNodeDescriptor` (static, trust-on-first-use node list), `build_packet`/`build_packet_to`, `process_packet` (`UnwrapOutcome::{Forward, Deliver, DropCover}`), fixed-size address encoding so a node never needs its own topology copy, `RELAY_DESTINATION_TAG`/`COVER_DESTINATION_TAG` final-hop markers (an unrecognised tag is refused, not guessed at)
- `transport` module: `MixTransport` replaces the previous `unimplemented!()` stub — real Sphinx-routed `send()` (fails closed, no fallback to a direct relay POST if the mix network is unreachable) and a `receive()` identical to `DirectTransport`'s (receive-path anonymization is explicitly out of scope for this sub-phase — see module docs)
- `error` module: `PardaError::MixRouting`
- `Cargo.toml`: `sphinx-packet = "0.7"`, `x25519-dalek = "3.0"`

#### Tests (`/protocol/tests`, `/mixnode/tests`)
- `protocol/tests/mixnet_tests.rs` — 9 tests: 3-hop packet round-trips envelope bit-identical; wrong key fails closed; drop-cover packets terminate as `DropCover` not `Deliver`; an unrecognised final-hop destination tag is refused; path-length and topology-size minimums enforced; `MixTransport::send` fails closed (returns `Err`, no relay fallback exists in the code path) when the first hop is unreachable
- `mixnode/tests/timing_correlation_tests.rs::test_send_to_arrival_timing_does_not_leak_flow_pairing_above_chance` — the sub-phase's deliverable gate: spins up 5 real mix-node daemons plus a real ephemeral relay (genuine loopback HTTP, not a mocked transport), routes 8 concurrent flows over independently-chosen 3-hop paths, and runs a permutation test on the Spearman rank correlation between send-order and relay-arrival-order for the true pairing against 5,000 random re-pairings. Documented explicitly as an empirical result bounded to the tested scale, not a formal anonymity proof
- `mixnode/tests/degradation_tests.rs` — 2 tests: a hop that silently drops a packet degrades the system to "message never arrives" (not misdelivery, and the sender's own HTTP response never reveals which downstream hop misbehaved); a hop with injected extra latency still delivers the correct plaintext, later than baseline

#### Documentation
- `docs/THREAT_MODEL.md`: §3.1 (GPA) — added a precise account of what Sub-Phase 2B does and does not defend against; §3.2 and §3.6 moved from "design target, not yet implemented" to implemented with test citations, including the honest empirical/scale-bounded framing of the timing-correlation result; §4 — added static-topology/no-directory-authority and receive-path-unanonymized as explicit out-of-scope items; §5 status table updated
- `docs/phase1-architecture.md`: new §12 addendum recording the `sphinx-packet` dependency decision and alternatives considered, the sender-sampled-delay design choice, and the "nodes carry no topology" decision
- `README.md`: Status table rows for send-path unlinkability, mix-network metadata resistance, and fail-safe degradation moved to ✅ Sub-Phase 2B; new limitations documented (static topology/no directory authority, receive-path not anonymized, cover traffic needs peer config, timing-correlation result is empirical/scale-bounded, mix-node identity is ephemeral); Components table updated with `/mixnode`

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
