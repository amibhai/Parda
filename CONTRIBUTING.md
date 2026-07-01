# Contributing to PARDA

Thank you for your interest in PARDA. Because this is a security-sensitive
research prototype, contributions are reviewed with a higher bar than a typical
open-source project.

## Before You Start

- Open an issue to discuss any proposed change before writing code.
- Check the [Phase 1 architecture decision record](docs/phase1-architecture.md)
  to understand why the stack was chosen and what is out of scope.
- Read the [Threat Model](docs/THREAT_MODEL.md) to understand what the system
  is — and is not — designed to protect against.

## Ground Rules

1. **No custom cryptographic primitives.** Use `libsignal-protocol` or another
   formally audited library. PRs that hand-roll AES, ECDH, or HMAC will be
   closed immediately.
2. **No telemetry or analytics SDKs.** PARDA must not phone home with any
   usage, crash, or diagnostic data.
3. **Private key material must never reach the Dart/Flutter layer.** All key
   operations stay in the native platform code (`SignalPlugin.kt` / future
   `SignalPlugin.swift`).
4. **Every crypto-layer change needs a test.** See `protocol/tests/crypto_tests.rs`
   for examples. Forward-secrecy and replay-rejection tests are mandatory for
   any session management change.
5. **Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/).**
   Prefix with `feat`, `fix`, `docs`, `test`, `chore`, or `refactor`.

## Development Setup

See the **Build Prerequisites** section of
[`docs/phase1-architecture.md`](docs/phase1-architecture.md) for Rust,
Flutter, and Android toolchain requirements.

## Submitting a Pull Request

1. Fork the repo and create a branch: `feat/your-feature` or `fix/short-desc`.
2. Make your changes, keeping commits small and logically grouped.
3. Ensure `cargo test -p parda-protocol` passes before opening the PR.
4. Fill in the PR description template (coming in a future commit).

## Security Disclosures

**Do not open a public GitHub issue for security vulnerabilities.**
Email the maintainers directly. A disclosure policy will be published
before the v0.1.0 release.

---

*CONTRIBUTING.md — draft. Full CLA and review process to be added before v0.1.0.*
