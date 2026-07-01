# PARDA — Developer Makefile
# Shortcuts for the most common dev tasks.
# Requires: Rust (cargo), Flutter, Docker (optional).

.PHONY: help build test server mobile lint clean

help:
	@echo ""
	@echo "  PARDA Developer Commands"
	@echo "  ────────────────────────────────────────────────"
	@echo "  make build       Build protocol + relay server (Rust)"
	@echo "  make test        Run all protocol crypto unit tests"
	@echo "  make server      Start relay server on 127.0.0.1:8080"
	@echo "  make mobile      Run Flutter app (requires connected device)"
	@echo "  make lint        Clippy (Rust) + flutter analyze"
	@echo "  make clean       Remove build artifacts"
	@echo ""

build:
	cargo build --workspace

test:
	cargo test -p parda-protocol -- --nocapture

server:
	PARDA_BIND=127.0.0.1:8080 cargo run -p parda-relay

mobile:
	cd mobile && flutter run

lint:
	cargo clippy --workspace -- -D warnings
	cd mobile && flutter analyze

clean:
	cargo clean
	cd mobile && flutter clean
