#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIST="$ROOT/dist"

mkdir -p "$DIST"
python3 -m build --no-isolation --sdist --wheel --outdir "$DIST" "$ROOT"

if command -v twine >/dev/null 2>&1; then
    twine check "$DIST"/bywaf-*.tar.gz "$DIST"/bywaf-*.whl
fi

printf 'pip artifacts written to %s\n' "$DIST"
