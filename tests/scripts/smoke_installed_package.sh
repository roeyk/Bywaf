#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BYWAF_CMD=${BYWAF_CMD:-bywaf}

$BYWAF_CMD --version | grep -q '^0\.9\.0$'
BYWAF_CMD="$BYWAF_CMD" "$ROOT/tests/scripts/smoke_plugin_install_paths.sh"

echo "installed package smoke test passed"
