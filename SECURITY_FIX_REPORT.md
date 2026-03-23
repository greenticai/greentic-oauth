# SECURITY_FIX_REPORT

Date: 2026-03-23 (UTC)
Role: Security Reviewer (CI)

## Inputs
- Dependabot alerts: `[]`
- Code scanning alerts: `[]`
- New PR dependency vulnerabilities: `[]`

## Analysis Summary
- Reviewed provided security alerts payload: no Dependabot or code-scanning findings were present.
- Reviewed provided PR vulnerability payload: no new dependency vulnerabilities were reported.
- Performed branch-vs-base dependency diff review against `origin/master`.

## PR Dependency Review
Commands run:
- `git diff --name-only origin/master...HEAD`
- `git diff --name-only origin/master...HEAD -- 'Cargo.toml' 'Cargo.lock' '**/Cargo.toml' '**/Cargo.lock' 'package.json' 'package-lock.json' '**/package.json' '**/package-lock.json'`
- `git diff origin/master...HEAD -- Cargo.toml components/oidc-ingress/Cargo.toml components/oidc-provider-runtime/Cargo.toml components/oidc-provider/Cargo.toml examples/axum-app/Cargo.toml`
- `git diff --unified=1 origin/master...HEAD -- Cargo.lock`
- `rg -n 'source = "git\\+' Cargo.lock`
- `rg -n '"resolved":\\s*"(git\\+|http://)' package-lock.json oauth-worker/package-lock.json oauth-worker/package.json`

Findings:
- Dependency-related changes exist in this PR branch:
  - `Cargo.toml`
  - `Cargo.lock`
  - `components/oidc-ingress/Cargo.toml` (new)
  - `components/oidc-provider/Cargo.toml` (new)
  - `components/oidc-provider-runtime/Cargo.toml` (new)
  - `examples/axum-app/Cargo.toml`
- Dependency deltas were predominantly additions of new internal component crates and version bumps (including `ureq 3.2.0 -> 3.3.0`, `rustls-webpki 0.103.9 -> 0.103.10`, `iri-string 0.7.10 -> 0.7.11`, `jni-sys 0.3.0 -> 0.3.1` plus transitive updates).
- No non-registry Rust sources (`git+`) were introduced in `Cargo.lock`.
- No insecure npm lockfile source URLs (`git+` or `http://`) were detected.
- Based on provided alert inputs and this dependency diff inspection, no newly introduced vulnerabilities were identified.

## Local Verification
Commands run:
- `cd oauth-worker && npm audit --audit-level=high --json`
- `cargo audit --version` (probe)

Results:
- `npm audit` could not reach npm registry in this CI environment (`getaddrinfo EAI_AGAIN registry.npmjs.org`), so live advisory lookup was unavailable.
- `cargo audit` tooling could not run in this CI environment because rustup temp path is read-only (`/home/runner/.rustup/tmp`, os error 30).

## Remediation Actions
- No code or dependency changes were required because no vulnerabilities were identified in provided alert payloads or PR dependency vulnerability input.
- No security fix patches were applied.

## Outcome
No security remediation actions were necessary for this run.
