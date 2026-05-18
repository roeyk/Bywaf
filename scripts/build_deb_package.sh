#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEBDIST="$ROOT/dist/deb"

if ! command -v dpkg-buildpackage >/dev/null 2>&1; then
    echo "dpkg-buildpackage not found; install Debian packaging tools to build .deb artifacts" >&2
    exit 1
fi

mkdir -p "$DEBDIST"
SOURCE=$(cd "$ROOT" && dpkg-parsechangelog -S Source)
VERSION=$(cd "$ROOT" && dpkg-parsechangelog -S Version)

(
    cd "$ROOT"
    dpkg-buildpackage -us -uc -b
)

shopt -s nullglob
artifacts=(
    "$ROOT"/../"$SOURCE"_"$VERSION"_*.deb
    "$ROOT"/../"$SOURCE"_"$VERSION"_*.changes
    "$ROOT"/../"$SOURCE"_"$VERSION"_*.buildinfo
)

if ((${#artifacts[@]} == 0)); then
    echo "no Debian artifacts were produced" >&2
    exit 1
fi

cp "${artifacts[@]}" "$DEBDIST/"
printf 'Debian artifacts written to %s\n' "$DEBDIST"
