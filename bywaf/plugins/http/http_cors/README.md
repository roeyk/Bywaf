# http_cors

Bundled-native Bywaf plugin for HTTP CORS posture checks.

## Behavior

`http_cors` sends one bounded CORS preflight-style `OPTIONS` request with a
synthetic `Origin` header. It emits an `http.cors` fact for the observed CORS
headers and promotes conservative finding candidates for clear unsafe posture:

- reflected arbitrary Origin with credentials
- reflected arbitrary Origin
- wildcard Origin with credentials

It does not send credentials, attempt bypasses, or exploit cross-origin access.

## Validate

```bash
PYTHONPATH=. pytest -q tests/framework_http_app/test_http_cors.py
python3 scripts/plugin_check.py --all --strict-inference
python3 scripts/plugin_graph.py --provider http.http_cors
```
