#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BYWAF_CMD=${BYWAF_CMD:-bywaf}
VERSION=$(python3 -c 'import pathlib, tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')

$BYWAF_CMD --version | grep -q "^${VERSION}$"
BYWAF_CMD="$BYWAF_CMD" "$ROOT/tests/scripts/smoke_plugin_install_paths.sh"

echo "installed package smoke test passed"
