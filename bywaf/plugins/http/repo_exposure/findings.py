"""Finding and fact payload mapping for repository exposure checks.

Provides normalized fact payloads and finding candidates for repository
metadata exposure observations.

Used by:
- repo exposure command orchestration: emit checked facts and findings.
- reporting tests: verify normalized grouping and evidence payloads."""

from __future__ import annotations

from typing import Any

from bywaf.findings import candidate_payload

from .models import DetectionStatus, GitConfigProbeResult


def result_payload(result: GitConfigProbeResult, *, family: str = "git_expose_check", check: str = "git_config") -> dict[str, Any]:
    """Return a JSON-safe fact payload for one Git config check."""
    return {
        "family": family,
        "check": check,
        "url": result.base_url,
        "checked_url": result.checked_url,
        "host": result.host,
        "port": result.port,
        "scheme": result.scheme,
        "status": result.status.value,
        "http_status": result.http_status,
        "final_url": result.final_url,
        "elapsed_ms": result.elapsed_ms,
        "evidence": result.evidence,
        "error": result.error,
    }


def candidate_from_detection(result: GitConfigProbeResult, *, source_tool: str = "git_expose_check") -> dict[str, Any] | None:
    """Return a normalized finding candidate for exposed Git config."""
    if result.status is not DetectionStatus.CANDIDATE:
        return None
    return candidate_payload(
        title="Exposed Git repository configuration",
        finding_class="web.exposure.git_config",
        severity="high",
        confidence="high",
        finding_scope="web_origin",
        target={
            "scheme": result.scheme,
            "host": result.host,
            "port": str(result.port),
            "path": "/.git/config",
            "url": result.checked_url,
        },
        identifiers={"cwe": ["CWE-538"]},
        affected=[{"url": result.checked_url}],
        evidence=f"{result.checked_url} returned Git configuration content: {result.evidence[:200]}",
        recommendation="Remove the .git directory from deployed web roots and block access to source-control metadata paths.",
        source={"tool": source_tool, "topic": "repo.git_config.checked"},
    )
