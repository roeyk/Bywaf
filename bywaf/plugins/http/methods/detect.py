"""Pure HTTP method probing logic.

Provides standard-library OPTIONS probing and Allow/Public header parsing
without depending on Bywaf runtime objects.

Used by:
- HTTP methods command orchestration: collect allowed-method posture facts.
- unit tests and plugin authors: validate probing logic outside Bywaf.
"""

from __future__ import annotations

import http.client

from bywaf.plugins.http.targets import HttpTarget as MethodTarget


def probe_methods(target: MethodTarget, *, timeout: float) -> dict[str, object]:
    """Perform one OPTIONS request and return method metadata.

    Called by: `command.run_http_methods()` once per scoped target.
    """
    # Pick the stdlib connection class that matches the resolved target scheme.
    connection_class = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection

    # Open an HTTP(S) connection to the target host and port.
    connection = connection_class(target.host, target.port, timeout=timeout)
    try:
        # Send an OPTIONS request to the target path.
        connection.request("OPTIONS", target.path)

        # Read the server's OPTIONS response.
        response = connection.getresponse()

        # Prefer the standard Allow header, then fall back to the older Public
        # header used by some servers.
        allow = response.getheader("Allow") or ""
        public = response.getheader("Public") or ""

        # Parse the selected header into sorted uppercase method tokens.
        methods = normalize_methods(allow or public)
        return {
            "ok": True,
            "status": response.status,
            "reason": response.reason,
            "allow": allow,
            "public": public,
            "methods": methods,
        }
    except (OSError, http.client.HTTPException, ValueError) as exc:
        # Preserve a structured error payload so one failed target does not
        # abort the rest of the commandlet run.
        return {"ok": False, "error": str(exc), "methods": []}
    finally:
        # Always release the socket-like connection object after probing.
        connection.close()


def normalize_methods(value: str) -> list[str]:
    """Return normalized HTTP method tokens from an Allow/Public header.

    Called by: `probe_methods()` after reading Allow/Public.
    """
    # Treat semicolons as separators too; some servers return non-standard
    # method lists, and this keeps parsing permissive without accepting
    # non-alpha tokens.
    methods = {
        token.strip().upper()
        for token in value.replace(";", ",").split(",")
        if token.strip().isalpha()
    }
    return sorted(methods)


__all__ = [
    "MethodTarget",
    "normalize_methods",
    "probe_methods",
]
