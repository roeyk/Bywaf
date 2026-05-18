#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

"$ROOT/scripts/build_pip_package.sh"
"$ROOT/scripts/build_deb_package.sh"
"$ROOT/scripts/build_rpm_package.sh"
