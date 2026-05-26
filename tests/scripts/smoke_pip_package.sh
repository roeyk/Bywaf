#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
VERSION=$(python3 -c 'import pathlib, tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

rm -rf "$ROOT/build" "$ROOT/bywaf.egg-info"
python3 -m build --no-isolation --sdist --wheel --outdir "$WORKDIR/dist" "$ROOT"
if command -v twine >/dev/null 2>&1; then
  twine check "$WORKDIR"/dist/*
fi
python3 -m venv --system-site-packages "$WORKDIR/venv"
"$WORKDIR/venv/bin/python" -m pip install --force-reinstall --no-deps "$WORKDIR"/dist/bywaf-*.whl >/dev/null

"$WORKDIR/venv/bin/bywaf" --version | grep -q "^${VERSION}$"
"$WORKDIR/venv/bin/python" - <<'PY'
from importlib import resources

from bywaf.registry import parse_package_plugin_config

entries = parse_package_plugin_config("bywaf.plugins", "plugins.toml")
assert "runtime.job" in entries
assert resources.files("bywaf.plugins").joinpath("plugins.toml").is_file()
PY

echo "pip package smoke test passed"
