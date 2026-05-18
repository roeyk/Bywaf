#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
VERSION=$(python3 -c 'import pathlib, tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')

if ! command -v rpmbuild >/dev/null 2>&1; then
  echo "rpmbuild not found; install the rpm package to run this smoke test" >&2
  exit 77
fi

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

mkdir -p "$WORKDIR/rpmbuild/SOURCES" "$WORKDIR/rpmbuild/SPECS" "$WORKDIR/dist"
python3 -m build --no-isolation --sdist --outdir "$WORKDIR/dist" "$ROOT"
cp "$WORKDIR/dist/bywaf-$VERSION.tar.gz" "$WORKDIR/rpmbuild/SOURCES/"
cp "$ROOT/packaging/rpm/bywaf.spec" "$WORKDIR/rpmbuild/SPECS/"

rpmbuild --define "_topdir $WORKDIR/rpmbuild" -ba "$WORKDIR/rpmbuild/SPECS/bywaf.spec"
test -f "$WORKDIR/rpmbuild/RPMS/noarch/bywaf-$VERSION-1.noarch.rpm"
test -f "$WORKDIR/rpmbuild/SRPMS/bywaf-$VERSION-1.src.rpm"

echo "rpm package smoke test passed"
