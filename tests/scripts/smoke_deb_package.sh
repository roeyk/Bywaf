#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
VERSION=$(python3 -c 'import pathlib, tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb not found; install Debian packaging tools to run this smoke test" >&2
  exit 77
fi

# Release directories may retain older packages, so validate the artifact that
# matches pyproject.toml instead of requiring dist/deb to contain only one .deb.
artifact="$ROOT/dist/deb/bywaf_${VERSION}-1_all.deb"
if [[ ! -f "$artifact" ]]; then
  "$ROOT/scripts/build_deb_package.sh"
fi
if [[ ! -f "$artifact" ]]; then
  printf 'expected Debian package artifact for version %s at %s\n' "$VERSION" "$artifact" >&2
  exit 1
fi

dpkg-deb --field "$artifact" Package | grep -q '^bywaf$'
dpkg-deb --field "$artifact" Version | grep -q "^${VERSION}-"

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo not found; cannot install Debian package for smoke test" >&2
  exit 77
fi

cleanup() {
  sudo apt-get remove -y bywaf >/dev/null 2>&1 || true
}
trap cleanup EXIT

sudo apt-get install -y "$artifact"
BYWAF_CMD=/usr/bin/bywaf "$ROOT/tests/scripts/smoke_installed_package.sh"

echo "Debian package smoke test passed"
