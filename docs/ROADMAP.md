# PARDA Roadmap: research prototype → audited v1.0

**Status:** adopted 2026-11-16. This is the project's only forward-looking plan. It supersedes the bare "Phase 5" row in the README and `phase1-architecture.md` §9. Wave W3 fulfils that documented Phase 5 (post-quantum).

**Rule for keeping this file honest:** update the [Progress](#7-progress) table in the same PR that completes a workstream, and never mark a workstream done ahead of the claims-registry entries that prove it.

## Context

PARDA is a messenger prototype with end-to-end encryption and metadata resistance. At adoption it had:
- ~17.6k lines of Rust in 9 crates
- a Flutter/Kotlin Android client (~6.9k lines)
- 180 Rust tests and 63 commits (Jun–Aug 2026)
- no releases

The core is real code, not scaffolding. The `stub`/`TODO` hits in the tree are prose. The only in-process fake is `cli/src/stub_relay.rs`, and it is a documented choice.

Two things set the project apart. Every ✅ it claims is backed by a named test, and its README lists ~51 limitations against itself. This roadmap keeps that discipline, makes CI enforce it, and closes every gap that can be closed in the right order.

**Maintainer decisions (2026-11-16):**
1. Reach audit grade first, then build the product.
2. No extra hardware; CI only. Claims that need hardware stay labelled unproven.
3. In scope: post-quantum hybrid crypto, a mix directory authority, formal verification, an external audit.
4. License: AGPL-3.0 throughout.

**Assumptions:**
- Nothing has been released and no deployment exists, so clean breaks are allowed: no data migrations, and fresh enrollment is fine.
- GitHub-hosted runners do all CI.

**Open question:** repository visibility. macOS runners are free only for public repositories. Resolve before W2.7.

---

## 1. Status at adoption

### Scorecard

| Area | Genuinely strong | Falls short |
|---|---|---|
| E2EE core (Rust) | Pinned libsignal v0.66.0, X3DH + Double Ratchet, forward-secrecy and replay tests | Classical crypto only. PQXDH ships upstream but is stubbed ([store.rs:283](../protocol/src/store.rs#L283)). Protocol store is in-memory only |
| Sealed sender | Implemented; tested against a 12-sender corpus | Certificates issued for any `(user_id, key)`. Not used by the app |
| Mix network | Sphinx (Nym crate), continuous-time exponential mixing, drop cover, two-leg rendezvous pull | **No replay protection.** Static TOFU topology, free-route paths, no client cover traffic, IP visible on the retrieval leg |
| Self-destruct | mlock'd derived key, rollback watermark, atomic read-trigger, forensic capstone tests | Plaintext buffer not locked. Unreachable from the app. OS Recents snapshots unprotected |
| Mesh | DTN relay with flood bounds, blinded dead-drops, N=30 simulation, real Android advertising | Two-device exchange never observed. iOS never compiled. No Windows backend. Cross-poll recurrence unmitigated |
| Relay / servers | SQLCipher at rest, survives restart, disciplined logging | **No mailbox authorization.** Key upload is last-write-wins. No caps or rate limits. A DB error causes a panic cascade |
| Android app | Works on a Pixel 8; QR key exchange; enforced verification; pinned-CA TLS | Separate protocol stack (libsignal-android 0.52). No sealed sender, mix routing, or self-destruct. Receives only in the foreground. Fetch is destructive |
| Engineering | 7 CI jobs, each isolating one claim; Ubuntu + Windows matrix | No clippy, fmt, deny, audit, coverage, fuzz, Miri, or MSRV gates. Toolchain floats. Actions pinned by tag. APK never built in CI. CI runs only for `main` |
| Documentation | Unusually candid; design notes for risky decisions | 17 internal contradictions. Glossary four phases stale. Tech Stack table claims gRPC/mTLS, Tor, Docker/K8s, Hypothesis — none exist. iOS Secure Enclave ✅ on a never-compiled platform |

### Findings from the 2026-11-16 review

None of these was recorded in the project's docs before this roadmap:
- W0.2 records F1–F10 in [THREAT_MODEL.md](THREAT_MODEL.md) and the README.
- F11 (engineering) and F12 (legal) are tracked here; W0.7 and W0.1 fix them.

Evidence line numbers refer to commit `b07c191`.

Severity: **P0** = a stated claim is false or remotely exploitable · **P1** = serious hardening gap · **P2** = behind the state of the art.

| # | Sev | Finding | Evidence |
|---|---|---|---|
| F1 | P0 | Anyone who knows or guesses a user ID can drain that user's mailbox (messages destroyed, metadata read), stage pulls for it, or delete messages. No route has any authorization layer, and IDs are free text typed at onboarding ("alice"). The relay's CORS policy also allows any origin, so any web page a user opens can do the same | `fetch_messages` → `store.drain` ([routes.rs:203](../server/src/routes.rs#L203)); router in [server/src/lib.rs](../server/src/lib.rs); [onboarding_screen.dart:207](../mobile/lib/screens/onboarding_screen.dart#L207) |
| F2 | P0 | Prekey upload is **last-write-wins**, not TOFU. Anyone can replace anyone's keys at any time, and two users who pick the same name silently overwrite each other. With F1, this allows interception of every new relay-fetched conversation. The threat model's "TOFU" label was inaccurate | `ON CONFLICT(user_id) DO UPDATE` ([store.rs:237](../server/src/store.rs#L237)) |
| F3 | P0 | Mix nodes keep no Sphinx replay-tag cache. Sphinx processing is deterministic, so a replayed packet produces identical output at an honest node, which links its input to its output. This falsified THREAT_MODEL.md §3.2 and the README's ✅ "degrades to loss/delay — never deanonymization" | `receive_packet` → `process_packet` → `schedule`, no check ([mixnode/src/routes.rs](../mixnode/src/routes.rs)) |
| F4 | P1 | Sender certificates are issued with no proof of key possession, so sealed-sender impersonation of unverified contacts is possible. Becomes live in the app once W2 turns sealed sender on | [routes.rs:89](../server/src/routes.rs#L89) |
| F5 | P1 | No `FLAG_SECURE`: the OS may save Recents thumbnails of open conversations to disk, and screen capture is allowed. No opt-out from IME personalized learning on message input | Absent from `MainActivity.kt` and every `TextField` |
| F6 | P1 | One DB error poisons the relay's mutex for good. `.expect()` inside `spawn_blocking` panics while `conn.lock().unwrap()` is held, and every later request then panics. 17 lock sites like this across server, client-store, mixnode, gateway | [store.rs:235](../server/src/store.rs#L235) |
| F7 | P1 | No per-mailbox caps and no relay/mixnode rate limits, so relay storage can be exhausted by anyone | `server/src/store.rs` caps only the cert TTL |
| F8 | P1 | The shipped app doesn't use the Rust core. There are 3 protocol implementations (Rust, Kotlin, never-compiled Swift) on 2 libsignal versions (0.66 / 0.52). This is the root of about a dozen documented limits; the app discloses it honestly | [settings_screen.dart:191](../mobile/lib/screens/settings_screen.dart#L191), [SignalPlugin.kt:332](../mobile/android/app/src/main/kotlin/com/parda/app/SignalPlugin.kt#L332) |
| F9 | P2 | No client-side cover traffic (Loopix sender Poisson rate / loop cover). A global passive adversary sees client send activity on the first hop. Topology is free-route, not stratified | [cover_traffic.rs](../mixnode/src/cover_traffic.rs), [mixnet.rs:226](../protocol/src/mixnet.rs#L226) |
| F10 | P2 | The `ring` TLS provider cannot do hybrid post-quantum key exchange (X25519MLKEM768) | [tls/Cargo.toml](../tls/Cargo.toml) |
| F11 | P2 | Two generations of crypto crates linked: curve25519-dalek 4+5, x25519-dalek 2+3, sha2 0.10+0.11, hkdf 0.12+0.13 | `Cargo.lock` |
| F12 | P2 | Three-way license conflict: `LICENSE` is GPL-3.0, `Cargo.toml` says Apache-2.0, README says "TBD". The libsignal dependency is AGPL-3.0 | `LICENSE`, [Cargo.toml:10](../Cargo.toml#L10), README § License |

None of these affected real users, because nothing has been deployed. The project's own rule still applies: **document first, then fix.**

---

## 2. Principles

**Preserved:**
- No custom cryptography; protocols are assembled only from published constructions.
- Every ✅ cites a passing test at its measured scope, and weaknesses are asserted under test.
- A design note comes before each workstream's riskiest decision.
- The relay stays a dumb pipe with no accounts; authorization uses keys, never identities.
- Wire changes are additive and versioned.
- Each purpose gets fresh, dedicated secrets.
- Dead-drop addresses stay counter-based, and mixing stays continuous-time.
- Mesh fails loudly rather than advertising a static ID.
- Pin the authority, not the leaf.

**Deliberate reversals** (each is recorded in its design note):

| Prior decision | Now | Why |
|---|---|---|
| TLS opt-in, because the tests used `http://` | On by default; plaintext only on loopback with an explicit flag | A `testkit/` TLS harness removes the original blocker |
| `ring` provider | `aws-lc-rs` | Needed for PQ TLS; opens a FIPS-validated path. Toolchain cost re-checked in CI, including the Android NDK |
| Kotlin/Swift protocol code over platform channels | One Rust core via `flutter_rust_bridge` v2 | Anticipated in ADR §4; eliminates F8 |
| Static topology "out of scope" (ADR §12) | Directory authority | Maintainer scope decision, 2026-11-16 |
| SURBs rejected (4.5A) | Revisited in W4.5 | Its preconditions now exist: directory, entry gateways, cover traffic |
| Forking Flutter text rendering rejected (4.5C §3) | Optional native rasterization (W6.4) | A different mechanism, which must justify itself |

---

## 3. The waves

```
W0 Truth & foundation ─► W1 Secure by default ─► W2 One Rust core ─┬─► W3 Post-quantum ──┐
                                                                    └─► W4 Mixnet SOTA ───┴─► W5 Assurance & audit ─► W6 Product
   continuous from W0: fuzzing, proptest, Kani; a formal model written alongside each new protocol's design note
```

### W0 — Truth & foundation (≈2–3 focused weeks)
- **W0.1 License.**
  - Verify libsignal's terms.
  - Set AGPL-3.0-only in `LICENSE`, `workspace.package.license`, the README, and SPDX headers.
  - Add the AGPL network-use source offer to the servers and the app's About screen.
  - Add a cargo-deny license allowlist so it cannot drift again.
- **W0.2 Record F1–F10 now.**
  - Add them to `THREAT_MODEL.md` §3/§4/§5 and the README.
  - Downgrade the replay claims until W1.4 lands.
  - Correct "TOFU" to "last-write-wins".
- **W0.3 Claims registry.** `docs/claims.toml` holds, per claim: id, statement, scope, status, tests, and threat-model section.
  - `cargo xtask claims` checks that every cited test exists (`cargo test -- --list`) and passed in this CI run.
  - The same command regenerates the README and THREAT_MODEL §5 tables between markers.
  - CI fails on drift.
  - Seed it from the existing README property table.
- **W0.4 Doc reconciliation.**
  - Fix the 17 contradictions, the glossary, and the README's stale opening sentence.
  - Tech Stack table: make each claim true or delete it.
  - Write retroactive design notes for 4.5B and 4.5E.
  - Add `SECURITY.md` (GitHub private vulnerability reporting).
  - Add a PR template with a "claims affected" checklist, and a `CLAUDE.md` with the ground rules.
- **W0.5 CI gates.**
  - `rust-toolchain.toml`, plus an MSRV job: the declared 1.75 is untested and current deps probably need a newer compiler.
  - `fmt --check`, and `clippy --all-targets -D warnings` with `unwrap_used`/`expect_used` denied in server-crate library code.
  - `cargo-deny` (advisories, licenses, bans, sources) and `cargo-llvm-cov` coverage.
  - Actions pinned by SHA, Dependabot, and CI on every branch.
  - An APK + `cargo-ndk` build job.
  - Strict Dart analysis (`strict-casts`, `strict-inference`, `strict-raw-types`).
- **W0.6 Fuzzing skeleton.** `fuzz/` with cargo-fuzz targets for every boundary that takes untrusted input:
  - `MessageEnvelope`, `PreKeyBundleJson`, contact card
  - Sphinx `receive_packet`, bp7 bundles, `PullRequest`, `AdvertToken`

  Runs in CI via ClusterFuzzLite.
- **W0.7 Hygiene.**
  - Merge `pinned-tls` → `main` (maintainer go-ahead).
  - Delete the merged `mobile-usable` branch and the empty `Parda/` directory.
  - Refresh dependencies (axum 0.8, rusqlite, …).
  - Collapse the duplicate crypto stacks (F11), recording any that can't be collapsed and why.

**Exit:** CI green with every gate · no license conflict · the registry generates the status tables · F1–F12 resolved or documented.

### W1 — Secure by default (≈4–6 weeks) → v0.2.0
Server, protocol, and CLI work lands in full. The Kotlin client gets only what it needs to keep working (request signing, the new ID format); everything else lands in the Rust SDK and reaches the app in W2. This avoids building client features twice.

- **W1.1 Self-certifying identity + mailbox authorization (F1, F2, F4).** Design note and ProVerif model.
  - `user_id = base32(hash(identity_key))`, so a relay-fetched bundle can be checked against the ID itself. This closes "first contact unprotected when keys come from the relay" whenever the ID arrived over a trusted channel.
  - Users keep local petnames. Trade-off: rotating the identity key changes the ID.
  - Every write (bundle refresh, cert issuance) and every mailbox read (fetch, delete, `stage_pull`) carries an identity-key signature over (route, ID, body hash, timestamp, nonce). Replay is blocked by a timestamp window plus a nonce cache.
  - The signature is libsignal's own XEdDSA, already used at [identity.rs:61](../protocol/src/identity.rs#L61), so no new primitive is introduced.
  - For mix-routed pulls, the signature rides inside the Sphinx payload, so 4.5A unlinkability is preserved.
  - Sending stays anonymous but requires a **delivery access token** (Signal's unidentified-access pattern), carried in the contact card. Strangers go through a rate-limited contact-request mailbox.

  *Tests:* an attacker who knows an ID cannot drain, delete, stage, overwrite, or get a cert for it · replays refused · receive-path anonymity suite still green.
- **W1.2 Acknowledged delivery.**
  - Replace drain-on-GET with lease + ACK.
  - Delete a message on ACK after durable persistence; redeliver it when the lease expires; enforce a retention TTL.
  - Closes "a failed decrypt loses the message".
- **W1.3 Secure defaults.**
  - TLS on by default; plaintext refused on non-loopback binds.
  - Gateway auth required by default.
  - Release builds fail without a pinned CA.
  - Drop the allow-any CORS layer: PARDA has no browser client.
  - All integration tests move to `testkit/`. It is built on `parda-tls`'s existing `pinned_authority`, `relay_certificate` and `serve` ([tls/src/lib.rs](../tls/src/lib.rs)), not new cert code.
- **W1.4 Sphinx replay protection (F3).**
  - Each node keeps a cache of replay tags derived from each hop's shared secret (Sphinx paper §4).
  - Check what `sphinx-packet` exposes; upgrade it if needed.
  - Memory stays bounded once epochs exist (W4.2). Until then the replay window is a stated residual.

  *Test:* a replayed packet is dropped at an honest node; the claims are restored.
- **W1.5 Robustness (F6).** Propagate errors, return 503 on DB failure, use non-poisoning locks, add tower-http `CatchPanicLayer`.
  *Test:* inject a DB failure; the next request still succeeds.
- **W1.6 Abuse resistance (F7).**
  - Per-mailbox and global storage caps.
  - In-memory rate limits on the relay and mixnode, explicit body limits, no IP logging.
  - Owner-only Windows ACL on the mixnode key file ([mixnode/src/identity.rs](../mixnode/src/identity.rs)).
- **W1.7 Android quick wins (F5).**
  - `FLAG_SECURE` by default, with a settings toggle and a stated trade-off.
  - `enableIMEPersonalizedLearning: false`, autocorrect and suggestions off on message input.
- **W1.8 Logging policy.**
  - A field allowlist enforced by a test: no user ID, IP, or sender ID at INFO or above.
  - Aggregate-only metrics.

### W2 — One Rust core everywhere (F8) (≈8–12 weeks)
- **W2.1 Design note: client architecture.**
  - A `flutter_rust_bridge` v2 boundary; keys never enter Dart.
  - A platform keystore wraps the SQLCipher DB key: Android Keystore, iOS Keychain, desktop OS keyring.
  - Plaintext crosses only as opaque handles.
- **W2.2 Persistent protocol store** in `client-store/`:
  - SQLCipher-backed `SignalProtocolStore`: sessions, prekeys, Kyber prekeys, identities, `TrustStore`.
  - Ports `PersistentSignalStore.kt` semantics: `identityMatchesVerified` enforcement and prekey replenishment.
- **W2.3 `parda-client` SDK.**
  - Covers send, the receive stream, contact cards, verification, all three self-destruct modes, burn, and mesh control.
  - The CLI becomes a thin SDK client, so the CLI and the app run identical code.
  - The CLI's prekey exchange moves to real HTTP, which closes that limitation.
- **W2.4 Flutter on the SDK.**
  - Delete `SignalPlugin.kt`, `PersistentSignalStore.kt`, `MessageStore.kt`, the `PlaintextPlugin` paths, and the libsignal-android dependency.
  - `AndroidMeshRadio` ([mobile-bridge/](../mobile-bridge/)) stays as the radio backend, driven from the core.
  - Sealed sender on by default, mix routing whenever a topology exists, and a self-destruct UI.
- **W2.5 Plaintext via Dart FFI external typed data.**
  - Rust-owned memory, zeroed and mlock'd on release, reusing the already-audited `PlaintextHandle` ([plaintext_ffi.rs:35](../protocol/src/plaintext_ffi.rs#L35)) and `secure_memory::lock`.
  - Removes the unscrubbable MethodChannel `Uint8List`.
  - The transient `String` from rendering remains a stated residual. Forensic test on an emulator.
- **W2.6 App architecture.**
  - Split the 450–600-line screens and services into view models (`provider` is already a dependency).
  - Golden tests, plus `integration_test` on an Android emulator in CI.
- **W2.7 iOS.**
  - The same core, built on macOS runners: a Flutter iOS build and simulator tests in CI.
  - `SignalPlugin.swift` is deleted.
  - `CoreBluetoothMeshRadio.swift` compiles in CI; BLE stays unproven (the simulator has no Bluetooth).

**Exit:** one protocol implementation and one libsignal version · the app sends sealed-sender, mix-routed messages · iOS builds and tests in CI.

### W3 — Post-quantum (the documented "Phase 5") (≈4–8 weeks, overlaps W4)
The design note opens with an inventory of every key agreement and signature, ranked by **harvest-now-decrypt-later (HNDL)** exposure. Key encapsulation (KEMs) comes first everywhere: recorded traffic can be decrypted later, but authentication cannot be broken retroactively.

| Surface | Approach | Basis (no custom crypto) |
|---|---|---|
| Session setup | **Mandatory PQXDH**: generate, sign, upload, and rotate ML-KEM (Kyber) prekeys plus a last-resort prekey; refuse classical-only bundles | Upstream libsignal, upgraded to its current release |
| Ratchet | Signal's SPQR triple ratchet, if the upgraded libsignal exposes it (verify) | Upstream libsignal |
| Transport TLS | X25519MLKEM768 hybrid key exchange. After W2, app traffic goes through the core's rustls | rustls + `aws-lc-rs` |
| Dead-drop key agreement | X-Wing hybrid KEM instead of bare X25519 | Published construction; libcrux or another reviewed implementation |
| Directory signatures (W4) | Hybrid Ed25519 + ML-DSA, using the IETF LAMPS composite construction, from day one | libcrux (formally verified) or aws-lc-rs |
| Sealed-sender certs | Stay XEdDSA (format owned by libsignal). Residual: a quantum adversary could forge them in real time, never retroactively | — |
| Sphinx hops | Spike: adopt a reviewed KEM-based mix format (Nym Outfox / Katzenpost-style) if a mature Rust implementation exists. Otherwise defer, with the residual (routing metadata, never content) asserted under test | An existing implementation, or none |

Add algorithm identifiers to the envelope and bundle formats (with a version bump), so a later ML-KEM-1024 / ML-DSA-87 CNSA 2.0 profile is configuration, not a protocol break.

*Tests:* PQXDH session setup · classical-only bundles refused · X-Wing known-answer tests · negotiated TLS group asserted to be X25519MLKEM768 · HNDL residuals asserted.

### W4 — Mix network to state of the art (≈10–16 weeks)
- **W4.1 Directory authority** (new `directory/` crate; design note and ProVerif model). A voting PKI in the style of Tor and Katzenpost:
  - 3–9 independently run authorities.
  - Each epoch, nodes submit signed descriptors: identity, epoch Sphinx key, layer, address, operator family.
  - Authorities vote a deterministic consensus, signed k-of-n with hybrid signatures.
  - Clients pin the authority keys (like the relay CA) and reject a stale consensus. Revocation is by omission.
  - This is honest-majority threshold signing, not a full BFT protocol, and it will be described exactly that way.
- **W4.2 Per-epoch Sphinx key rotation.**
  - Bounds the replay cache (completing W1.4) and how long a compromised key stays useful.
  - Mix-key verification becomes an enforced control, not the "documented workflow" of 4.5D.
- **W4.3 Stratified topology.**
  - The consensus assigns layers; a path takes one node per layer, never two from the same operator family, weighted by bandwidth.
  - Replaces `choose_path`'s free-route sampling ([mixnet.rs:226](../protocol/src/mixnet.rs#L226)).
  - Peers come from the consensus, so the "≥3 `MIXNODE_PEERS`" precondition for cover traffic goes away.
- **W4.4 Client cover traffic (F9).**
  - Loopix model: the client sends at Poisson rate λ, and real messages take dummy slots.
  - Client and mix loop cover detects active (n−1) attacks.
  - Mobile profiles: "max anonymity" and "battery saver", with the saver's exposure of send timing stated.
  - Bandwidth measured in bytes/hour, like the mesh battery tests.
- **W4.5 Full receive-path unlinkability** (design note).
  - Persistent entry gateways plus SURB replies (Nym's model), so the relay never sees a client's IP.
  - Precondition: verify SURB support in `sphinx-packet`.
- **W4.6 Anonymity evaluation harness.**
  - Entropy of the sender anonymity set across a sweep of path length, λ, μ, node count, and load.
  - Simulated long-term statistical disclosure attacks.
  - Reproducible results, positioned against published bounds (the anonymity trilemma). The claim stays explicitly empirical.

### W5 — Assurance capstone & external audit (≈8–12 weeks, plus 1–3 months audit lead time) → v1.0
- **W5.1 Code-level verification.**
  - `proptest`: envelope round-trips, the self-destruct state machine, relay queue no-loss/no-duplication.
  - Kani bounded proofs:
    - The ~12 `unsafe` sites (`plaintext_ffi`, `secure_memory`, `self_destruct`, `mobile-bridge/src/ffi.rs`) have no double-free or use-after-zeroize. This code shipped a double-free once already.
    - No parser can panic.
  - Miri on the pure-Rust paths.
  - `loom` on the read-trigger mutex and the relay leases.
  - Fuzzing grows into continuous corpora.
- **W5.2 Formal protocol models** (`formal/`, ProVerif primary, run nightly):
  - Mailbox auth and self-certifying IDs
  - Sealed sender with cert issuance
  - Rendezvous-pull unlinkability (as observational equivalence)
  - Dead-drop addressing
  - Contact-card bootstrapping
  - Directory consensus

  PQXDH and the Double Ratchet are not re-modelled; we cite the published analyses. Formal methods prove the protocol logic in the symbolic model. They **do not** turn resistance to timing correlation into a proof; that stays empirical (W4.6).
- **W5.3 Constant-time evidence.**
  - Run `dudect`-style tests on every secret-dependent comparison PARDA owns: API keys, fingerprints, tokens, dead-drop matching.
  - For primitives, rely on libcrux's verified secret independence.
- **W5.4 Supply chain.**
  - Reproducible builds: pinned toolchain, `SOURCE_DATE_EPOCH`, `--remap-path-prefix`, a deterministic APK built in Docker, and a script anyone can run to verify.
  - CycloneDX SBOM.
  - Sigstore/cosign keyless signing.
  - SLSA Build L3 provenance (`slsa-github-generator`).
- **W5.5 Audit pack.** Frozen commit, architecture overview, threat model, claims registry with test results, formal-model results, known-issues list.
- **W5.6 Engagement.**
  - Candidate firms: NCC Group, Trail of Bits, Cure53, Radically Open Security, Least Authority.
  - Candidate funding (eligibility to be verified): OTF Red Team Lab, NLnet NGI Zero.
  - Then remediate and publish the report. Each finding gets a regression test and a registry update.

### W6 — Product (post-audit, ≈12–20 weeks)
- **W6.1 Background delivery.**
  - An Android foreground service; cover traffic needs one anyway.
  - WorkManager for low-power mode.
  - Optional UnifiedPush or content-free FCM/APNs wakeups, each with its metadata cost stated (the provider learns wake timing).
- **W6.2 Mesh evidence without hardware.** Two spikes:
  - Two Android emulators over netsim virtual BLE.
  - BlueZ virtual controllers (`btvirt` or Bumble) for `bluer`.

  If either runs headless in CI, it is the project's first two-node exchange. It is labelled **virtual RF**, never real RF. Otherwise the claim stays unproven.
- **W6.3 Mesh completeness.**
  - Status UI.
  - A Windows backend on WinRT BLE (`windows` crate): compiled, unproven on radio.
  - Android Wi-Fi Aware/Direct via the same JNI pattern as BLE. "No viable Rust crate" stops mattering once the platform backend is Kotlin. Unverifiable in CI, and labelled so.
  - Cross-poll recurrence mitigation: the re-poll cap and re-addressing named in 4C §3a, measured before and after.
- **W6.4 Hardened render mode** (optional, research).
  - Rust rasterizes message text (cosmic-text) into a texture, so no Dart `String` ever exists.
  - Costs (accessibility labels, text selection) and residual (a bitmap in graphics memory) stated.
  - Forensic test on an emulator.
- **W6.5 Operations.**
  - Distroless, non-root Dockerfiles.
  - A full-network `docker-compose`: 3 authorities, a 3-layer mixnet, relay, gateway.
  - Helm charts.
  - Runbooks: key ceremony for the CA and authority keys (offline root, optional YubiKey), rotation, backup.
  - Monitoring that collects no metadata.
- **W6.6 Distribution.**
  - Signed GitHub releases.
  - F-Droid, which suits reproducible builds.
  - Play Store optional; TestFlight/App Store needs an Apple developer account.
  - Optional Flutter desktop apps, nearly free once there is one core.
- **W6.7 UX.** Onboarding, verification flows, i18n, accessibility.

**After v1.0 (not on the critical path):**
- Groups via MLS (RFC 9420, OpenMLS)
- Multi-device
- Bug bounty
- CNSA 2.0 profile
- FIPS mode for TLS via the aws-lc-rs FIPS module. libsignal is not FIPS-validated, so FIPS 140-3 for PARDA as a whole would be a separate lab engagement.

---

## 4. Milestones & effort

| Release | After | Means |
|---|---|---|
| v0.2.0 | W1 | Secure by default, every P0 fixed |
| v0.5.0 | W2 + W3 | One core; post-quantum E2EE and TLS |
| v0.9.0 | W4 + W5.1–5.5 | Audit freeze |
| v1.0.0 | W5.6 remediation | Audited |

**≈48–77 solo-equivalent focused weeks**, a rough estimate. W3 and W4 overlap.

## 5. What stays true after v1.0 (stated, never "solved")
These are limits of physics, the platform, or upstream code, not gaps left open:
- A device's presence on a broadcast radio is detectable.
- A memory dump taken before expiry recovers the message.
- libsignal's `PrivateKey` doesn't zeroize, so burn stays weaker than self-destruct.
- A rooted device can rewrite the rollback watermark.
- A device that is powered off and never runs again never fires its self-destruct.
- The render-time `String` remains unless W6.4 ships.
- Every claim that needs hardware remains unproven: two devices on real RF, power draw, CoreBluetooth on a device.

## 6. Verification
- **Per workstream:** its exit criteria are claims-registry entries that cite named tests, and `cargo xtask claims` passes.
- **Every PR:**
  - Rust: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo deny check`, `cargo test --workspace`, `cargo llvm-cov`.
  - ClusterFuzzLite PR fuzzing.
  - Mobile: `flutter analyze`, `flutter test`, the APK build, and the iOS build (from W2).
- **Nightly:**
  - Long fuzz runs, ProVerif models, Kani proofs.
  - Integration tests on an Android emulator.
  - Reproducible-build check: two independent builds must produce identical hashes.
  - The anonymity harness.
- **End-to-end acceptance (from W4):** under `docker compose up`:
  - Two CLI clients and two Android emulators exchange PQXDH, sealed-sender, mix-routed messages with cover traffic on.
  - A packet replayed at a mix node is dropped.
  - An attacker client fails to drain, overwrite, or impersonate.

## 7. Progress

| Workstream | Status |
|---|---|
| W0.2 Record F1–F10 | Done — recorded in THREAT_MODEL.md v0.6.0 and the README; nothing fixed yet |
| W0.1 License | Next |
| W0.3–W0.7 | Not started |
| W1–W6 | Not started |
