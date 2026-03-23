.PHONY: build test run fmt fmt-check clippy lint check docker oauth-oidc-pack-build oauth-oidc-pack-clean

build:
	cargo build --workspace

test:
	cargo test --workspace

run:
	cargo run -p greentic-oauth-broker

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

lint: clippy

check: fmt-check clippy test

docker:
	@echo "docker target not yet implemented"

oauth-oidc-pack-build:
	./scripts/build-oauth-oidc-pack.sh

oauth-oidc-pack-clean:
	./scripts/clean-oauth-oidc-pack.sh
