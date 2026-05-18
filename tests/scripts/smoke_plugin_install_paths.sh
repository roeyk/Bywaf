#!/usr/bin/env bash
set -euo pipefail

BYWAF_CMD=${BYWAF_CMD:-"python3 -m bywaf"}
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

write_plugin() {
  local root=$1
  local entry=$2
  local name=$3
  local source=$4
  local dir="$root/$entry"
  mkdir -p "$dir"
  cat >"$dir/plugin.py" <<PY
from bywaf.plugin import CommandSpec


class SmokePlugin:
    spec = CommandSpec("$name", "$source plugin", emits=("$name.event",))

    def run(self, context, args, input_events):
        yield {"source": "$source"}


def plugin():
    return SmokePlugin()
PY
  printf '{"origin": "%s"}\n' "$source" >"$dir/defaults.json"
}

run_probe() {
  local root=$1
  local config=$2
  local commandlet=$3
  local expected=$4
  local output

  output=$(
    $BYWAF_CMD \
      --database "$WORKDIR/$commandlet.sqlite3" \
      --plugin-root "$root" \
      --plugin-config "$config" \
      run "$commandlet"
  )
  grep -q "$expected" <<<"$output"
}

USER_ROOT="$WORKDIR/home/alice/.bywaf/plugins"
SYSTEM_ROOT="$WORKDIR/usr/share/bywaf/plugins"

write_plugin "$USER_ROOT" "local/userprobe" "userprobe" "user-local"
cat >"$USER_ROOT/plugins.yaml" <<'YAML'
default_plugins:
  - local/userprobe
YAML

write_plugin "$SYSTEM_ROOT" "site/systemprobe" "systemprobe" "system-wide"
cat >"$SYSTEM_ROOT/plugins.yaml" <<'YAML'
default_plugins:
  - site/systemprobe
YAML

run_probe "$USER_ROOT" "$USER_ROOT/plugins.yaml" "userprobe" "user-local"
run_probe "$SYSTEM_ROOT" "$SYSTEM_ROOT/plugins.yaml" "systemprobe" "system-wide"

echo "plugin install-path smoke test passed"
