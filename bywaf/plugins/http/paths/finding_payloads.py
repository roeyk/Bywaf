"""Finding payload construction for interesting HTTP path observations.

Called by: `paths.findings.finding_for_path()` exports and `http_paths` when an
observed path should become a structured finding.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass

from bywaf.event.schema_objects import HttpPathObserved
from bywaf.finding import candidate_payload

from .rules import (
    ADMIN_PATHS,
    CLOUD_APP_CONFIG_PATHS,
    DEPENDENCY_MANIFEST_PATHS,
    SENSITIVE_CONFIG_PATHS,
    SOURCE_MAP_SUFFIX,
    VCS_METADATA_PATHS,
    is_backup_archive_path,
    is_database_dump_path,
)


@dataclass(frozen=True, slots=True)
class PathFindingDetails:
    """Static normalized finding fields for one HTTP path observation.

    Constructed by: `path_finding_details()`.
    Used by: `finding_for_path()` to keep finding payloads consistent across
    path classes without duplicating title/class/severity metadata.
    """

    title: str
    finding_class: str
    severity: str
    target_scope: dict[str, str] | None = None
    identifiers: dict[str, list[str]] | None = None
    recommendation: str = ""


GIT_CONFIG_RECOMMENDATION = (
    "Remove the .git directory from deployed web roots and block access to source-control metadata paths."
)
SOURCE_META_RECOMMENDATION = (
    "Remove source-control metadata from deployed web roots and block access to revision-control metadata paths."
)
SOURCE_MAP_RECOMMENDATION = (
    "Publish production assets without source maps, or restrict source-map access to authorized debugging workflows."
)
DEP_META_RECOMMENDATION = (
    "Remove dependency manifests and lockfiles from deployed web roots, or restrict access to build metadata."
)
SENSITIVE_CONFIG_RECOMMENDATION = (
    "Remove sensitive configuration files from deployed web roots and rotate any exposed credentials."
)
CLOUD_APP_CONFIG_RECOMMENDATION = (
    "Remove cloud or application configuration files from deployed web roots and rotate any exposed credentials."
)


def finding_for_path(observed: HttpPathObserved) -> dict[str, object] | None:
    """Return a finding candidate for clearly risky HTTP path observations."""
    if not observed.interesting:
        return None
    path = observed.path.casefold()
    details = path_finding_details(path, observed)
    return candidate_payload(
        title=details.title,
        finding_class=details.finding_class,
        severity=details.severity,
        confidence_basis="content_indicator",
        target={"url": observed.url, "host": observed.host, "path": observed.path},
        target_scope=details.target_scope or {"kind": "web_route", "value": observed.url},
        affected=[{"url": observed.url, "host": observed.host, "path": observed.path}],
        identifiers=details.identifiers,
        evidence=path_evidence(observed),
        recommendation=details.recommendation,
        source={"tool": "http_paths", "topic": "http.path"},
        finding_scope="",
    )


def path_finding_details(path: str, observed: HttpPathObserved) -> PathFindingDetails:
    """Return normalized finding details for one interesting path."""
    origin_scope = {"kind": "web_origin", "value": origin_for_observed_path(observed)}
    cwe_538 = {"cwe": ["CWE-538"]}
    if observed.path == "/.git/config":
        return PathFindingDetails(
            "Exposed Git repository configuration",
            "web.exposure.git_config",
            "high",
            origin_scope,
            cwe_538,
            GIT_CONFIG_RECOMMENDATION,
        )
    if path in VCS_METADATA_PATHS:
        return PathFindingDetails(
            "Exposed source-control metadata",
            "web.exposure.source_control_metadata",
            "high",
            origin_scope,
            cwe_538,
            SOURCE_META_RECOMMENDATION,
        )
    exact_details = exact_path_finding_details(observed.path)
    if exact_details:
        return exact_details
    artifact_details = artifact_path_finding_details(path, origin_scope, cwe_538)
    if artifact_details:
        return artifact_details
    return PathFindingDetails(f"Interesting HTTP path exposed: {observed.path}", "web.path.interesting", "low")


def exact_path_finding_details(path: str) -> PathFindingDetails | None:
    """Return normalized finding details for exact known risky paths."""
    exact_paths = {
        "/server-status": PathFindingDetails("Exposed Apache server-status endpoint", "web.server_status.exposed", "medium"),
        "/.env": PathFindingDetails("Exposed environment configuration file", "web.config.env_exposed", "high"),
        "/actuator/env": PathFindingDetails("Exposed Spring Boot environment endpoint", "web.spring.actuator_env_exposed", "high"),
    }
    if path in exact_paths:
        return exact_paths[path]
    if path.casefold() in ADMIN_PATHS:
        return PathFindingDetails("Exposed administrative login surface", "web.admin_interface.exposed", "low")
    return None


def artifact_path_finding_details(
    path: str,
    origin_scope: dict[str, str],
    cwe_538: dict[str, list[str]],
) -> PathFindingDetails | None:
    """Return normalized finding details for artifact-like paths."""
    if is_database_dump_path(path):
        return PathFindingDetails("Exposed database dump artifact", "web.backup.database_dump_exposed", "high")
    if is_backup_archive_path(path):
        return PathFindingDetails("Exposed backup or source archive", "web.backup.archive_exposed", "medium")
    if path.endswith(SOURCE_MAP_SUFFIX):
        return PathFindingDetails(
            "Exposed JavaScript source map",
            "web.exposure.source_map",
            "medium",
            origin_scope,
            cwe_538,
            SOURCE_MAP_RECOMMENDATION,
        )
    if path in DEPENDENCY_MANIFEST_PATHS:
        return PathFindingDetails(
            "Exposed dependency metadata",
            "web.exposure.dependency_metadata",
            "medium",
            origin_scope,
            cwe_538,
            DEP_META_RECOMMENDATION,
        )
    if path in SENSITIVE_CONFIG_PATHS:
        return PathFindingDetails(
            "Exposed sensitive configuration file",
            "web.exposure.sensitive_config",
            "high",
            origin_scope,
            cwe_538,
            SENSITIVE_CONFIG_RECOMMENDATION,
        )
    if path in CLOUD_APP_CONFIG_PATHS:
        return PathFindingDetails(
            "Exposed cloud or application configuration file",
            "web.exposure.cloud_app_config",
            "high",
            origin_scope,
            cwe_538,
            CLOUD_APP_CONFIG_RECOMMENDATION,
        )
    return None


def origin_for_observed_path(observed: HttpPathObserved) -> str:
    """Return the web origin for an observed HTTP path."""
    parsed = urllib.parse.urlparse(observed.url)
    return f"{parsed.scheme}://{parsed.netloc}"


def path_evidence(observed: HttpPathObserved) -> str:
    """Return operator-facing evidence for one interesting HTTP path."""
    details = [f"{observed.url} returned HTTP {observed.status}"]
    if observed.content_type:
        details.append(f"content-type={observed.content_type}")
    if observed.length is not None:
        details.append(f"length={observed.length}")
    if observed.title:
        details.append(f"title={observed.title}")
    return "; ".join(details)
