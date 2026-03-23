#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

rm -f "${ROOT_DIR}/dist/packs/oauth-oidc.gtpack"
rm -f "${ROOT_DIR}/packs/oauth-oidc/components/oidc-provider-runtime/component.wasm"
rm -f "${ROOT_DIR}/packs/oauth-oidc/components/oidc-ingress/component.wasm"

echo "Cleaned OIDC executable pack artifacts."
