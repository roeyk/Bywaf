"""Pure HTTP authentication challenge probing logic.

Provides standard-library request probing and authentication challenge parsing
without depending on Bywaf runtime objects.

Used by:
- HTTP auth command orchestration: collect authentication posture facts.
- unit tests and plugin authors: validate probing logic outside Bywaf.
"""

from __future__ import annotations

import http.client

from bywaf.plugins.http.targets import HttpTarget as AuthTarget


def probe_auth(target: AuthTarget, *, method: str, timeout: float) -> dict[str, object]:
    """Perform one HTTP request and return auth challenge metadata.

    Called by: `command.run_http_auth()` once per scoped target.
    """
    # Pick the stdlib connection class that matches the resolved target scheme.
    connection_class = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection

    # Open an HTTP(S) connection to the target host and port.
    connection = connection_class(target.host, target.port, timeout=timeout)
    try:
        # Send the configured probe method to the target path.
        connection.request(method, target.path)

        # Read the server's HTTP response.
        response = connection.getresponse()

        # Get all response headers because auth challenges can appear multiple
        # times and can come from either origin or proxy authentication.
        challenges = response.getheaders()
        www_authenticate = [
            value
            for name, value in challenges
            if name.lower() == "www-authenticate" and value.strip()
        ]
        proxy_authenticate = [
            value
            for name, value in challenges
            if name.lower() == "proxy-authenticate" and value.strip()
        ]

        # Normalize challenge header values into scheme tokens and realm names.
        schemes = normalize_schemes(www_authenticate + proxy_authenticate)
        realms = challenge_realms(www_authenticate + proxy_authenticate)
        return {
            "ok": True,
            "status": response.status,
            "reason": response.reason,
            "www_authenticate": www_authenticate,
            "proxy_authenticate": proxy_authenticate,
            "schemes": schemes,
            "realms": realms,
        }
    except (OSError, http.client.HTTPException, ValueError) as exc:
        # Preserve a structured error payload so one failed target does not
        # abort the rest of the commandlet run.
        return {"ok": False, "error": str(exc), "schemes": [], "realms": []}
    finally:
        # Always release the socket-like connection object after probing.
        connection.close()


def normalize_schemes(challenges: list[str]) -> list[str]:
    """Return normalized authentication scheme tokens from challenge headers.

    Called by: `probe_auth()` after reading authentication challenge headers.
    """
    schemes = []
    for challenge in challenges:
        # The auth scheme is the leading token before challenge parameters.
        token = challenge.strip().split(None, 1)[0].strip(",")
        if token and token.replace("-", "").isalnum():
            schemes.append(token.upper())
    return sorted(set(schemes))


def challenge_realms(challenges: list[str]) -> list[str]:
    """Return realm values from simple WWW-Authenticate challenge headers.

    Called by: `probe_auth()` after reading authentication challenge headers.
    """
    realms = []
    for challenge in challenges:
        # This intentionally handles the common `realm="..."` form without
        # trying to implement a full HTTP auth parameter parser.
        lowered = challenge.lower()
        marker = 'realm="'
        start = lowered.find(marker)
        if start == -1:
            continue
        start += len(marker)
        end = challenge.find('"', start)
        if end != -1:
            realms.append(challenge[start:end])
    return sorted(set(realms))


__all__ = [
    "AuthTarget",
    "challenge_realms",
    "normalize_schemes",
    "probe_auth",
]
