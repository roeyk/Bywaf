#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
VERSION=$(python3 -c 'import pathlib, tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')

if ! command -v rpmbuild >/dev/null 2>&1; then
  echo "rpmbuild not found; install the rpm package to run this smoke test" >&2
  exit 77
fi
if ! command -v rpm2cpio >/dev/null 2>&1 || ! command -v cpio >/dev/null 2>&1; then
  echo "rpm2cpio and cpio are required to extract the RPM payload for smoke testing" >&2
  exit 77
fi

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

mkdir -p "$WORKDIR/rpmbuild/SOURCES" "$WORKDIR/rpmbuild/SPECS" "$WORKDIR/dist" "$WORKDIR/installroot"
rm -rf "$ROOT/build" "$ROOT/bywaf.egg-info"
python3 -m build --no-isolation --sdist --outdir "$WORKDIR/dist" "$ROOT"
cp "$WORKDIR/dist/bywaf-$VERSION.tar.gz" "$WORKDIR/rpmbuild/SOURCES/"
cp "$ROOT/packaging/rpm/bywaf.spec" "$WORKDIR/rpmbuild/SPECS/"

rpmbuild --nodeps --define "_topdir $WORKDIR/rpmbuild" --define "bywaf_version $VERSION" -ba "$WORKDIR/rpmbuild/SPECS/bywaf.spec"
RPM="$WORKDIR/rpmbuild/RPMS/noarch/bywaf-$VERSION-1.noarch.rpm"
test -f "$RPM"
test -f "$WORKDIR/rpmbuild/SRPMS/bywaf-$VERSION-1.src.rpm"

(
  cd "$WORKDIR/installroot"
  rpm2cpio "$RPM" | cpio -id --quiet --no-absolute-filenames
)
test -x "$WORKDIR/installroot/usr/bin/bywaf"
SITE_PACKAGES=$(find "$WORKDIR/installroot/usr" -type d -name site-packages -print -quit)
if [[ -z "$SITE_PACKAGES" ]]; then
  echo "could not find extracted RPM site-packages directory" >&2
  exit 1
fi
BYWAF_CMD="env PYTHONPATH=$SITE_PACKAGES $WORKDIR/installroot/usr/bin/bywaf" "$ROOT/tests/scripts/smoke_installed_package.sh"

echo "rpm package smoke test passed"
