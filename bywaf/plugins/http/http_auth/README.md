# http_auth

Bundled Bywaf HTTP authentication posture plugin.

## Validate

```bash
python3 - <<'PY'
from bywaf.registry import PluginRegistry
PluginRegistry({}).load_package_entry("bywaf.plugins", "http.http_auth")
PY
python3 scripts/plugin_check.py --all --strict-inference
PYTHONPATH=. pytest -q tests/framework_http_app/test_http_auth.py
```

## Contract

- Module: `bywaf.plugins.http.http_auth`
- Commandlet: `http_auth`
- Consumes: `port.open`
- Emits: `http.auth`, `finding.candidate`

## Behavior

`http_auth` sends one HEAD request by default for each explicit target or
upstream `port.open` event. It records `WWW-Authenticate` and
`Proxy-Authenticate` challenge metadata and promotes conservative candidate
findings for Basic authentication over cleartext HTTP, authentication
challenges on administrative-looking paths, and Basic challenges without a
realm value.

The commandlet does not send credentials, attempt login, or perform any auth
bypass checks.
