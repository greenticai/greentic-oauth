.PHONY: build test run fmt fmt-check clippy lint check docker oauth-oidc-generic-pack-build oauth-oidc-generic-pack-clean

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

oauth-oidc-generic-pack-build:
	./scripts/build-oauth-oidc-generic-pack.sh

oauth-oidc-generic-pack-clean:
	./scripts/clean-oauth-oidc-generic-pack.sh
