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
    """Return the canonical `/.git/config` URL for a base endpoint.

    Called by: `probe_git_config()` before making the exposure probe request.
    """
    # Preserve scheme/authority and replace any input path with the Git config
    # metadata path checked by this plugin.
    parsed = urllib.parse.urlparse(base_url)
    path = "/.git/config"
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def probe_git_config(opener, endpoint: dict[str, Any], *, timeout: float, user_agent: str) -> GitConfigProbeResult:
    """Probe one HTTP endpoint for public `/.git/config` content.

    Called by: `command.run_git_config_check()` once per scoped endpoint.
    """
    # Prefer the final URL from upstream HTTP probing when present; otherwise
    # fall back to the original endpoint URL.
    base_url = str(endpoint.get("final_url") or endpoint.get("url") or "")
    checked_url = git_config_url(base_url)
    start = time.monotonic()

    # Build a bounded GET request for the repository metadata path.
    request = urllib.request.Request(checked_url, method="GET", headers={"User-Agent": user_agent})
    try:
        # Read only a bounded sample. The signature is near the top of real Git
        # config files, and keeping the sample small protects the event store.
        # Open the request through the provided opener.
        with opener.open(request, timeout=timeout) as response:
            # Read a small response sample and classify it.
            body = response.read(4096)
            return classify_response(endpoint, checked_url, response.status, response.geturl(), body, elapsed_ms(start))
    except urllib.error.HTTPError as exc:
        # Some servers expose sensitive content with an error status or branded
        # error wrapper; classify the bounded body the same way as a 2xx response.
        # Read the error response body because it can still contain Git config
        # content.
        body = exc.read(4096)
        return classify_response(endpoint, checked_url, exc.code, exc.geturl(), body, elapsed_ms(start))
    except urllib.error.URLError as exc:
        # Preserve a structured error result so one failed endpoint does not
        # abort the rest of the commandlet run.
        return base_result(endpoint, checked_url, DetectionStatus.ERROR, elapsed_ms=elapsed_ms(start), error=str(exc.reason))


def classify_response(
    endpoint: dict[str, Any],
    checked_url: str,
    http_status: int,
    final_url: str,
    body: bytes,
    elapsed: int,
) -> GitConfigProbeResult:
    """Classify a bounded response body as exposed Git config or safe.

    Called by: `probe_git_config()` for normal and HTTP-error responses.
    """
    # Decode the bounded byte sample to text for signature matching.
    sample = body.decode("utf-8", errors="replace")
    if http_status == 200 and looks_like_git_config(sample):
        # Build a candidate result with evidence capped for event storage and
        # reporting.
        return base_result(
            endpoint,
            checked_url,
            DetectionStatus.CANDIDATE,
            http_status=http_status,
            final_url=final_url,
            elapsed_ms=elapsed,
            evidence=sample[:400],
        )
    # Any non-matching response is safe for this specific passive check.
    return base_result(endpoint, checked_url, DetectionStatus.SAFE, http_status=http_status, final_url=final_url, elapsed_ms=elapsed)


def looks_like_git_config(text: str) -> bool:
    """Return whether a response sample looks like a Git config file.

    Called by: `classify_response()` after decoding the response sample.
    """
    # Match the canonical Git config core stanza and repository format key.
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
    """Build a result from an endpoint payload and classification fields.

    Called by: `probe_git_config()` and `classify_response()`.
    """
    # Reconstruct normalized target fields from endpoint payload data, falling
    # back to parsed URL components when explicit fields are absent.
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
    """Return elapsed milliseconds since `start`.

    Called by: `probe_git_config()` for probe timing.
    """
    # Convert monotonic seconds to integer milliseconds for JSON-safe events.
    return int((time.monotonic() - start) * 1000)


def default_port(scheme: str) -> int:
    """Return the default port for an HTTP scheme.

    Called by: `base_result()` when endpoint payloads omit a port.
    """
    return 443 if scheme == "https" else 80
