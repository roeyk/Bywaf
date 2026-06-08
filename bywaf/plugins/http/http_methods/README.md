# http_methods

Bundled Bywaf HTTP method posture plugin.

## Validate

```bash
python3 - <<'PY'
from bywaf.registry import PluginRegistry
PluginRegistry({}).load_package_entry("bywaf.plugins", "http.http_methods")
PY
python3 scripts/plugin_check.py --all --strict-inference
PYTHONPATH=. pytest -q tests/framework_http_app/test_http_methods.py
```

## Contract

- Module: `bywaf.plugins.http.http_methods`
- Commandlet: `http_methods`
- Consumes: `port.open`
- Emits: `http.methods`, `finding.candidate`

## Behavior

`http_methods` sends one OPTIONS request per explicit target or upstream
`port.open` event. It records the advertised methods from `Allow` or `Public`
headers and promotes enabled TRACE, write-capable, or WebDAV methods into
candidate findings for report review.
