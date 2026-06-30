# Changelog

All notable changes to **PARDA** (Privacy-Assured Resilient Defense Architecture) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Initial project scaffold — repository structure, `.gitignore`, and directory layout for `core/`, `mix-node/`, `client/`, and `docs/`
- `README.md` — project overview, problem statement, core features, architecture phases, tech stack, status & limitations, threat model summary, and placeholder setup instructions
- `docs/THREAT_MODEL.md` (draft) — adversary model definition covering global passive adversary, active relay compromise, and device-seizure threat vectors; formal anonymity guarantees deferred to Phase 2 review
- `LICENSE` placeholder — license selection pending (candidates: Apache 2.0 / MIT)
- `CONTRIBUTING.md` placeholder — contributor guidelines and CLA notice to be published before v0.1.0

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
