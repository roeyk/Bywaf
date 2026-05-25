"""Pure probing and classification logic for repository exposure checks.

Provides HTTP probing and response classification for exposed repository
metadata without depending on Bywaf runtime objects.

Used by:
- repo exposure command orchestration: detect exposed `.git/config` files.
- unit tests and plugin authors: validate detection logic outside Bywaf."""

from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .models import DetectionStatus, GitConfigProbeResult


def git_config_url(base_url: str) -> str:
    """Return the canonical `/.git/config` URL for a base endpoint."""
    parsed = urllib.parse.urlparse(base_url)
    path = "/.git/config"
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def probe_git_config(opener, endpoint: dict[str, Any], *, timeout: float, user_agent: str) -> GitConfigProbeResult:
    """Probe one HTTP endpoint for public `/.git/config` content."""
    base_url = str(endpoint.get("final_url") or endpoint.get("url") or "")
    checked_url = git_config_url(base_url)
    start = time.monotonic()
    request = urllib.request.Request(checked_url, method="GET", headers={"User-Agent": user_agent})
    try:
        # Read only a bounded sample. The signature is near the top of real Git
        # config files, and keeping the sample small protects the event store.
        with opener.open(request, timeout=timeout) as response:
            body = response.read(4096)
            return classify_response(endpoint, checked_url, response.status, response.geturl(), body, elapsed_ms(start))
    except urllib.error.HTTPError as exc:
        # Some servers expose sensitive content with an error status or branded
        # error wrapper; classify the bounded body the same way as a 2xx response.
        body = exc.read(4096)
        return classify_response(endpoint, checked_url, exc.code, exc.geturl(), body, elapsed_ms(start))
    except urllib.error.URLError as exc:
        return base_result(endpoint, checked_url, DetectionStatus.ERROR, elapsed_ms=elapsed_ms(start), error=str(exc.reason))


def classify_response(
    endpoint: dict[str, Any],
    checked_url: str,
    http_status: int,
    final_url: str,
    body: bytes,
    elapsed: int,
) -> GitConfigProbeResult:
    """Classify a bounded response body as exposed Git config or safe."""
    sample = body.decode("utf-8", errors="replace")
    if http_status == 200 and looks_like_git_config(sample):
        return base_result(
            endpoint,
            checked_url,
            DetectionStatus.CANDIDATE,
            http_status=http_status,
            final_url=final_url,
            elapsed_ms=elapsed,
            evidence=sample[:400],
        )
    return base_result(endpoint, checked_url, DetectionStatus.SAFE, http_status=http_status, final_url=final_url, elapsed_ms=elapsed)


def looks_like_git_config(text: str) -> bool:
    """Return whether a response sample looks like a Git config file."""
    normalized = text.lower()
    return "[core]" in normalized and "repositoryformatversion" in normalized


def base_result(
    endpoint: dict[str, Any],
    checked_url: str,
    status: DetectionStatus,
    *,
    http_status: int | None = None,
    final_url: str = "",
    elapsed_ms: int = 0,
    evidence: str = "",
    error: str = "",
) -> GitConfigProbeResult:
    """Build a result from an endpoint payload and classification fields."""
    base_url = str(endpoint.get("final_url") or endpoint.get("url") or "")
    parsed = urllib.parse.urlparse(base_url)
    scheme = str(endpoint.get("scheme") or parsed.scheme or "")
    host = str(endpoint.get("host") or parsed.hostname or "")
    port = int(endpoint.get("port") or default_port(scheme))
    return GitConfigProbeResult(
        base_url=base_url,
        checked_url=checked_url,
        host=host,
        port=port,
        scheme=scheme,
        status=status,
        http_status=http_status,
        final_url=final_url,
        elapsed_ms=elapsed_ms,
        evidence=evidence,
        error=error,
    )


def elapsed_ms(start: float) -> int:
    """Return elapsed milliseconds since `start`."""
    return int((time.monotonic() - start) * 1000)


def default_port(scheme: str) -> int:
    """Return the default port for an HTTP scheme."""
    return 443 if scheme == "https" else 80
