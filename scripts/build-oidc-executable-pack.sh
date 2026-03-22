#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACK_DIR="${ROOT_DIR}/packs/oidc-executable"
OUT_DIR="${ROOT_DIR}/dist/packs"
GT_OUT="${OUT_DIR}/oauth-oidc-executable.gtpack"

ensure_wasm_target() {
  if rustup target list --installed | grep -qx "wasm32-wasip2"; then
    return
  fi

  if ! command -v rustup >/dev/null 2>&1; then
    echo "rustup is required to install wasm32-wasip2 target" >&2
    exit 1
  fi

  local active_toolchain
  active_toolchain="$(rustup show active-toolchain | awk '{print $1}')"
  echo "==> Installing missing target wasm32-wasip2 for ${active_toolchain}"
  rustup target add wasm32-wasip2 --toolchain "${active_toolchain}"
}

ensure_wasm_target

echo "==> Building OIDC executable components (wasm32-wasip2)"
cargo build --release -p oidc-provider-runtime --target wasm32-wasip2
cargo build --release -p oidc-ingress --target wasm32-wasip2

RUNTIME_WASM="${ROOT_DIR}/target/wasm32-wasip2/release/oidc_provider_runtime.wasm"
INGRESS_WASM="${ROOT_DIR}/target/wasm32-wasip2/release/oidc_ingress.wasm"

if [[ ! -f "${RUNTIME_WASM}" ]]; then
  echo "missing runtime wasm: ${RUNTIME_WASM}" >&2
  exit 1
fi
if [[ ! -f "${INGRESS_WASM}" ]]; then
  echo "missing ingress wasm: ${INGRESS_WASM}" >&2
  exit 1
fi

mkdir -p "${PACK_DIR}/components/oidc-provider-runtime"
mkdir -p "${PACK_DIR}/components/oidc-ingress"
mkdir -p "${OUT_DIR}"

cp "${RUNTIME_WASM}" "${PACK_DIR}/components/oidc-provider-runtime/component.wasm"
cp "${INGRESS_WASM}" "${PACK_DIR}/components/oidc-ingress/component.wasm"

echo "==> Building gtpack"
(
  cd "${PACK_DIR}"
  greentic-pack build \
    --allow-pack-schema \
    --no-update \
    --in . \
    --gtpack-out "${GT_OUT}"
)

echo "Built ${GT_OUT}"
