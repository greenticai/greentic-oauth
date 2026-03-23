#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

rm -f "${ROOT_DIR}/dist/packs/oauth-oidc-generic.gtpack"
rm -f "${ROOT_DIR}/packs/oauth-oidc-generic/components/oidc-provider-runtime/component.wasm"
rm -f "${ROOT_DIR}/packs/oauth-oidc-generic/components/oidc-ingress/component.wasm"

echo "Cleaned OIDC executable pack artifacts."
