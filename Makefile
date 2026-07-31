# PARDA — Developer Makefile
# Shortcuts for the most common dev tasks.
# Requires: Rust (cargo), Flutter, Docker (optional).

.PHONY: help build test server mobile lint clean

help:
	@echo ""
	@echo "  PARDA Developer Commands"
	@echo "  ────────────────────────────────────────────────"
	@echo "  make build       Build protocol + relay server (Rust)"
	@echo "  make test        Run all workspace tests (protocol + relay)"
	@echo "  make server      Start relay server on 127.0.0.1:8080 (dev-only DB key — see target)"
	@echo "  make mobile      Run Flutter app (requires connected device)"
	@echo "  make lint        Clippy (Rust) + flutter analyze"
	@echo "  make clean       Remove build artifacts"
	@echo ""

build:
	cargo build --workspace

test:
	cargo test --workspace -- --nocapture

# PARDA_DB_KEY here is a fixed dev-only value — never reuse it for a
# deployment that will hold real data. See server/src/store.rs module docs.
server:
	PARDA_BIND=127.0.0.1:8080 PARDA_DB_KEY=dev-only-insecure-key-do-not-deploy cargo run -p parda-relay

mobile:
	cd mobile && flutter run

lint:
	cargo clippy --workspace -- -D warnings
	cd mobile && flutter analyze

clean:
	cargo clean
	cd mobile && flutter clean
