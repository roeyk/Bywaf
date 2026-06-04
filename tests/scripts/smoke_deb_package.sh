#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
VERSION=$(python3 -c 'import pathlib, tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb not found; install Debian packaging tools to run this smoke test" >&2
  exit 77
fi

shopt -s nullglob
artifacts=("$ROOT"/dist/deb/bywaf_*_all.deb)
if ((${#artifacts[@]} == 0)); then
  "$ROOT/scripts/build_deb_package.sh"
  artifacts=("$ROOT"/dist/deb/bywaf_*_all.deb)
fi
if ((${#artifacts[@]} != 1)); then
  printf 'expected exactly one Debian package artifact, found %d\n' "${#artifacts[@]}" >&2
  exit 1
fi
artifact=${artifacts[0]}

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
