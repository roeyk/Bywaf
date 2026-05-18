#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=$(python3 -c 'import pathlib, tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')
DIST="$ROOT/dist"
RPMDIST="$DIST/rpm"
TOPDIR="$RPMDIST/rpmbuild"

if ! command -v rpmbuild >/dev/null 2>&1; then
    echo "rpmbuild not found; install the rpm package to build RPM artifacts" >&2
    exit 1
fi

mkdir -p "$DIST"
python3 -m build --no-isolation --sdist --outdir "$DIST" "$ROOT"

rm -rf "$TOPDIR"
mkdir -p "$TOPDIR/BUILD" "$TOPDIR/BUILDROOT" "$TOPDIR/RPMS" "$TOPDIR/SOURCES" "$TOPDIR/SPECS" "$TOPDIR/SRPMS"
cp "$DIST/bywaf-$VERSION.tar.gz" "$TOPDIR/SOURCES/"
cp "$ROOT/packaging/rpm/bywaf.spec" "$TOPDIR/SPECS/"

rpmbuild --nodeps --define "_topdir $TOPDIR" -ba "$TOPDIR/SPECS/bywaf.spec"

printf 'rpm artifacts written under %s\n' "$RPMDIST"
