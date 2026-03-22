#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

rm -f "${ROOT_DIR}/dist/packs/oauth-oidc-executable.gtpack"
rm -f "${ROOT_DIR}/packs/oidc-executable/components/oidc-provider-runtime/component.wasm"
rm -f "${ROOT_DIR}/packs/oidc-executable/components/oidc-ingress/component.wasm"

echo "Cleaned OIDC executable pack artifacts."

