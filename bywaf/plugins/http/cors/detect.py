"""Pure HTTP CORS probing logic.

Provides standard-library OPTIONS probing and CORS response normalization
without depending on Bywaf runtime objects.

Used by:
- HTTP CORS command orchestration: collect CORS posture facts.
- unit tests and plugin authors: validate probing logic outside Bywaf.
"""

from __future__ import annotations

import http.client

from bywaf.plugins.http.http_targets import HttpTarget as CorsTarget


def probe_cors(
    target: CorsTarget,
    *,
    origin: str,
    request_method: str,
    timeout: float,
) -> dict[str, object]:
    """Perform one CORS preflight-style request and return response metadata.

    Called by: `command.run_http_cors()` once per scoped target.
    """
    # Pick the stdlib connection class that matches the resolved target scheme.
    connection_class = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection

    # Open an HTTP(S) connection to the target host and port.
    connection = connection_class(target.host, target.port, timeout=timeout)

    # Build the CORS request headers that simulate a browser cross-origin
    # preflight check for the requested method.
    headers = {
        "Origin": origin,
        "Access-Control-Request-Method": request_method,
    }
    try:
        # Send the OPTIONS request with the Origin and requested-method headers.
        connection.request("OPTIONS", target.path, headers=headers)

        # Read the server's CORS preflight response.
        response = connection.getresponse()

        # Extract the CORS posture headers this commandlet evaluates.
        allow_origin = response.getheader("Access-Control-Allow-Origin") or ""
        allow_credentials = response.getheader("Access-Control-Allow-Credentials") or ""
        allow_methods = response.getheader("Access-Control-Allow-Methods") or ""
        vary = response.getheader("Vary") or ""

        # Return both raw header values and normalized booleans for finding
        # generation and display/reporting.
        return {
            "ok": True,
            "status": response.status,
            "reason": response.reason,
            "allow_origin": allow_origin,
            "allow_credentials": allow_credentials,
            "allow_methods": allow_methods,
            "vary": vary,
            "reflected_origin": same_origin_value(allow_origin, origin),
            "wildcard_origin": allow_origin.strip() == "*",
            "credentials_allowed": truthy_header(allow_credentials),
        }
    except (OSError, http.client.HTTPException, ValueError) as exc:
        # Preserve a structured error payload so one failed target does not
        # abort the rest of the commandlet run.
        return {"ok": False, "error": str(exc)}
    finally:
        # Always release the socket-like connection object after probing.
        connection.close()


def same_origin_value(value: str, origin: str) -> bool:
    """Return whether a response origin exactly matches the request origin.

    Called by: `probe_cors()` when deriving `reflected_origin`.
    """
    # Compare stripped, casefolded values; CORS origin matching is exact for
    # this passive check.
    return value.strip().casefold() == origin.strip().casefold()


def truthy_header(value: str) -> bool:
    """Return whether a response header means true.

    Called by: `probe_cors()` for Access-Control-Allow-Credentials.
    """
    # The CORS credentials header is only enabled by the literal true value.
    return value.strip().casefold() == "true"
