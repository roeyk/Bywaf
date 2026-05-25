"""Pure HTTP header probing logic.

Provides standard-library HTTP HEAD probing and response normalization without
depending on Bywaf runtime objects.

Used by:
- HTTP header command orchestration: collect header facts for events.
- unit tests and plugin authors: validate detection logic outside Bywaf."""

from __future__ import annotations

import http.client

from .models import HeaderProbeResult, HeaderTarget


def fetch_headers(target: HeaderTarget, *, timeout: float) -> HeaderProbeResult:
    """Fetch HEAD response metadata for one target."""
    connection_cls = http.client.HTTPSConnection if target.use_ssl else http.client.HTTPConnection
    conn = connection_cls(target.host, port=target.port, timeout=timeout)
    try:
        conn.request("HEAD", "/")
        response = conn.getresponse()
        return HeaderProbeResult(target=target, status=response.status, headers=dict(response.headers))
    finally:
        conn.close()
