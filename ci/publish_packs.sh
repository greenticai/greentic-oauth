#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

command -v oras >/dev/null 2>&1 || { echo "oras is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

OCI_REGISTRY="${OCI_REGISTRY:-ghcr.io}"
OCI_NAMESPACE="${OCI_NAMESPACE:-${GITHUB_REPOSITORY_OWNER:-greentic-ai}}"
OCI_REPO="${OCI_REPO:-packs/oauth}"
PACK_VERSION="${PACK_VERSION:-}"
if [ -z "${PACK_VERSION}" ]; then
  PACK_VERSION="$(python3 - <<'PY'
from pathlib import Path
import tomllib
data = tomllib.loads(Path("Cargo.toml").read_text())
print(data.get("workspace", {}).get("package", {}).get("version", "0.0.0"))
PY
)"
fi
PACK_VERSION="${PACK_VERSION#v}"
PUBLISH_LATEST="${PUBLISH_LATEST:-0}"

if ! compgen -G "dist/packs/*.gtpack" >/dev/null; then
  echo "No built packs found under dist/packs" >&2
  exit 1
fi

python3 - "${PACK_VERSION}" "${OCI_REGISTRY}" "${OCI_NAMESPACE}" "${OCI_REPO}" "${PUBLISH_LATEST}" <<'PY'
from pathlib import Path
import json
import subprocess
import sys

pack_version, registry, namespace, repo, publish_latest = sys.argv[1:]
root = Path.cwd()
lock_path = root / "packs.lock.json"
lock = json.loads(lock_path.read_text(encoding="utf-8")) if lock_path.exists() else {"version": pack_version, "packs": []}
packs_by_name = {entry["name"]: entry for entry in lock.get("packs", [])}

for pack_path in sorted((root / "dist" / "packs").glob("*.gtpack")):
    name = pack_path.stem
    repo_path = f"{registry}/{namespace}/{repo}/{name}"
    version_ref = f"{repo_path}:{pack_version}"
    subprocess.run(
        [
            "oras",
            "push",
            version_ref,
            f"{pack_path}:application/vnd.greentic.gtpack.v1+zip",
        ],
        check=True,
    )
    if publish_latest.lower() in {"1", "true", "yes"}:
        latest_ref = f"{repo_path}:latest"
        subprocess.run(
            [
                "oras",
                "push",
                latest_ref,
                f"{pack_path}:application/vnd.greentic.gtpack.v1+zip",
            ],
            check=True,
        )

    entry = packs_by_name.setdefault(name, {"name": name})
    entry["version"] = pack_version
    entry["reference"] = f"oci://{version_ref}"
    if publish_latest.lower() in {"1", "true", "yes"}:
        entry["latest_reference"] = f"oci://{repo_path}:latest"

lock["version"] = pack_version
lock["packs"] = [packs_by_name[name] for name in sorted(packs_by_name)]
lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
PY

echo "Published OAuth packs to ${OCI_REGISTRY}/${OCI_NAMESPACE}/${OCI_REPO}"
