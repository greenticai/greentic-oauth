# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

greentic-oauth is the OAuth 2.0 / OIDC broker for the Greentic platform. It provides reusable WASM components for OAuth authentication flows and card placeholder resolution, packaged as `.gtpack` extensions.

## Build & Test

```bash
# Full workspace (exclude deprecated broker)
cargo build --workspace --exclude greentic-oauth-broker
cargo test --workspace --exclude greentic-oauth-broker
cargo clippy --workspace --exclude greentic-oauth-broker -- -D warnings
cargo fmt --all --check

# Build WASM components
cargo build --release -p oidc-provider-runtime --target wasm32-wasip2
cargo build --release -p oidc-ingress --target wasm32-wasip2

# Build pack
./scripts/build-oauth-oidc-generic-pack.sh
```

Rust edition 2024, pinned via `rust-toolchain.toml`. Cargo.lock is committed.

## Architecture

### Crates

| Crate | Purpose |
|-------|---------|
| `greentic-oauth-core` | Shared OAuth types, token helpers, provider primitives |
| `greentic-oauth-broker` | Multi-tenant broker (deprecated, marked for deletion) |
| `greentic-oauth-host` | Host-side Wasmtime linker wiring |
| `greentic-oauth-sdk` | Client SDK and WIT host bindings |
| `greentic-oauth-client` | Lightweight HTTP client for initiating flows |

### Components (WASM, target: wasm32-wasip2)

| Component | Purpose |
|-----------|---------|
| `oauth-card` | Generic OAuth card placeholder resolution library (pure logic, no WIT) |
| `oidc-provider` | Shared OIDC logic library (`OidcComponent`, authorize URL, token exchange) |
| `oidc-provider-runtime` | WASM runtime component (exports `schema-core-api`, imports `secrets-store`) |
| `oidc-ingress` | OAuth callback normalization (code/state/error parsing) |

### Capabilities Provided (via oauth-oidc-generic pack)

| Capability ID | Operation | What it does |
|---------------|-----------|-------------|
| `greentic.cap.oauth.broker.v1` | `oauth.initiate_auth` | Generate OAuth authorize URL with PKCE |
| `greentic.cap.oauth.broker.v1` | `oauth.get_access_token` | Exchange auth code for access token |
| `greentic.cap.oauth.broker.v1` | `oauth.request_resource_token` | Refresh expired access token |
| `greentic.cap.oauth.card.v1` | `oauth.card.resolve` | Resolve OAuth placeholders in Adaptive Cards |

### oauth-card Library

Generic, provider-agnostic library for resolving OAuth placeholders in Adaptive Cards. Designed for reuse by any OAuth provider (OIDC, SAML, custom).

Resolves:
- `{{oauth.start_url}}` in text fields
- `oauth://start` in `Action.OpenUrl` actions
- `{{oauth.teams.connectionName}}` for Teams-native providers (or removes for non-native)

Includes URL scheme validation (rejects non-HTTP(S) URIs) and enum-based downgrade types.

### Pack Structure

```
packs/oauth-oidc-generic/
  pack.yaml              # Pack manifest with capability offers
  assets/setup.yaml      # Interactive setup questions
  schemas/               # JSON Schema for config validation
  components/            # Compiled .wasm files (build artifact)
```

## Key Patterns

- **schema-core-api**: All runtime components export this WIT interface (`describe`, `validate_config`, `healthcheck`, `invoke`)
- **secrets-store**: Components import secrets via WIT, resolved by the host at runtime
- **Dual op names**: Operations accept both kebab-case (`authorize-url`) and dotted (`oauth.initiate_auth`) names for compatibility
- **Capability offers**: Declared in `pack.yaml` under `greentic.ext.capabilities.v1`, auto-discovered by `CapabilityRegistry` at runtime

## Git Conventions

Do NOT add Claude co-author attribution to commits or PRs.

## Parent Workspace

This project is part of the Greentic platform ecosystem. See the workspace root `CLAUDE.md` for workspace-level conventions including shared crates, WASM component model, pack/bundle formats, and i18n patterns.
