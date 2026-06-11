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
    """Fetch HEAD response metadata for one target.

    Called by: `command.run_http_headers()` after target resolution and scope
    filtering.
    """
    # Pick the stdlib connection class that matches the target scheme.
    connection_cls = http.client.HTTPSConnection if target.use_ssl else http.client.HTTPConnection

    # Open the HTTP(S) connection object for the target host and port.
    conn = connection_cls(target.host, port=target.port, timeout=timeout)
    try:
        # Use HEAD because this commandlet only needs response metadata; plugin
        # authors can swap in GET in their own detect.py if body evidence matters.
        # Send a HEAD request for the origin root path.
        conn.request("HEAD", "/")

        # Read the HTTP response object produced by the server.
        response = conn.getresponse()

        # Copy status and headers into plain model data for tests and event
        # packaging; no Bywaf runtime objects are needed beyond this point.
        return HeaderProbeResult(target=target, status=response.status, headers=dict(response.headers))
    finally:
        # Always release the socket-like connection object after the probe.
        conn.close()
