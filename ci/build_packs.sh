#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

mkdir -p dist/packs

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
command -v zip >/dev/null 2>&1 || { echo "zip is required" >&2; exit 1; }
command -v shasum >/dev/null 2>&1 || { echo "shasum is required" >&2; exit 1; }

PACK_VERSION="${PACK_VERSION:-$(python3 - <<'PY'
from pathlib import Path
import tomllib
data = tomllib.loads(Path("Cargo.toml").read_text())
print(data.get("workspace", {}).get("package", {}).get("version", "0.0.0"))
PY
)}"
export PACK_VERSION

GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

python3 - <<'PY' > "${tmp_dir}/providers.json"
from pathlib import Path
import json

providers = []
for yaml_path in sorted(Path("configs/providers").glob("*.yaml")):
    provider_id = None
    for line in yaml_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("id:"):
            provider_id = line.split(":", 1)[1].strip()
            break
    if not provider_id:
        raise SystemExit(f"missing id in {yaml_path}")
    provider_json = yaml_path.with_suffix(".provider.json")
    providers.append(
        {
            "id": provider_id,
            "yaml": str(yaml_path),
            "json": str(provider_json) if provider_json.exists() else None,
        }
    )

print(json.dumps(providers))
PY

python3 - "${tmp_dir}/providers.json" "${PACK_VERSION}" "${GIT_SHA}" "${BUILD_TIME}" "${tmp_dir}" <<'PY'
from pathlib import Path
import json
import shutil
import subprocess
import sys

providers = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
version = sys.argv[2]
git_sha = sys.argv[3]
build_time = sys.argv[4]
tmp_root = Path(sys.argv[5])
root = Path.cwd()
dist_dir = root / "dist" / "packs"
lock_entries = []

for provider in providers:
    provider_id = provider["id"]
    pack_id = f"oauth-{provider_id}"
    stage_dir = tmp_root / pack_id
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True, exist_ok=True)

    source_yaml = root / provider["yaml"]
    shutil.copy2(source_yaml, stage_dir / "provider.yaml")
    assets = ["provider.yaml"]
    if provider["json"]:
        source_json = root / provider["json"]
        shutil.copy2(source_json, stage_dir / "provider.json")
        assets.append("provider.json")

    metadata = {
        "pack_id": pack_id,
        "provider_id": provider_id,
        "version": version,
        "source_repo": "greentic-oauth",
        "build_time": build_time,
        "git_sha": git_sha,
        "assets": assets,
    }
    (stage_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    out_file = dist_dir / f"{pack_id}.gtpack"
    if out_file.exists():
        out_file.unlink()
    subprocess.run(
        ["zip", "-qr", str(out_file), "."],
        cwd=stage_dir,
        check=True,
    )

    sha256 = subprocess.check_output(
        ["shasum", "-a", "256", str(out_file)],
        text=True,
    ).split()[0]
    lock_entries.append(
        {
            "name": pack_id,
            "provider_id": provider_id,
            "version": version,
            "file": str(out_file.relative_to(root)),
            "sha256": sha256,
        }
    )

lock = {"version": version, "packs": lock_entries}
(root / "packs.lock.json").write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
PY

echo "Built OAuth packs:"
find dist/packs -maxdepth 1 -type f -name '*.gtpack' | sort
