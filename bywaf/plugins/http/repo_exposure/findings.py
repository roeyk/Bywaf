"""Finding and fact payload mapping for repository exposure checks.

Provides normalized fact payloads and finding candidates for repository
metadata exposure observations.

Used by:
- repo exposure command orchestration: emit checked facts and findings.
- reporting tests: verify normalized grouping and evidence payloads."""

from __future__ import annotations

from typing import Any

from bywaf.finding import candidate_payload

from .models import DetectionStatus, GitConfigProbeResult


def result_payload(result: GitConfigProbeResult, *, family: str = "git_expose_check", check: str = "git_config") -> dict[str, Any]:
    """Return a JSON-safe fact payload for one Git config check.

    Called by: `command.run_git_config_check()` before yielding checked facts.
    """
    # Convert the domain result object into the plugin-owned
    # `repo.git_config.checked` event payload.
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
    """Return a normalized finding candidate for exposed Git config.

    Called by: `command.run_git_config_check()` after one check result.
    """
    if result.status is not DetectionStatus.CANDIDATE:
        return None

    # Exposed repository metadata is an origin-level issue. The affected URL is
    # kept as evidence, while grouping uses the origin so future repository
    # exposure checks on the same web service can collapse together.
    # Package the candidate in the common finding.candidate contract.
    return candidate_payload(
        title="Exposed Git repository configuration",
        finding_class="web.exposure.git_config",
        severity="high",
        confidence="high",
        confidence_basis="safe_probe",
        finding_scope="web_origin",
        target={
            "scheme": result.scheme,
            "host": result.host,
            "port": str(result.port),
            "path": "/.git/config",
            "url": result.checked_url,
        },
        identifiers={"cwe": ["CWE-538"]},
        affected=[{"url": result.checked_url, "host": result.host, "path": "/.git/config"}],
        evidence=git_config_evidence(result),
        recommendation="Remove the .git directory from deployed web roots and block access to source-control metadata paths.",
        source={"tool": source_tool, "topic": "repo.git_config.checked"},
    )


def git_config_evidence(result: GitConfigProbeResult) -> str:
    """Return operator-facing evidence for an exposed Git config response.

    Called by: `candidate_from_detection()` when packaging a finding.
    """
    # Start with the core proof: the checked URL returned Git config content.
    details = [f"{result.checked_url} returned Git configuration content"]
    if result.http_status is not None:
        # Include status when available because redirects/error wrappers can
        # affect triage.
        details.append(f"http_status={result.http_status}")
    if result.final_url and result.final_url != result.checked_url:
        # Preserve the final URL when the server redirected the probe.
        details.append(f"final_url={result.final_url}")
    if result.evidence:
        # Cap evidence text for concise report output.
        details.append(f"sample={result.evidence[:200]}")
    return "; ".join(details)
