"""Compatibility facade for HTTP path classification and finding payloads.

Used by: `http_paths` and older tests/imports that still expect both path
classification helpers and finding payload builders in one module.
"""

from __future__ import annotations

from .http_path_rules import (
    is_backup_archive_path as is_backup_archive_path,
    is_database_dump_path as is_database_dump_path,
    is_interesting_path as is_interesting_path,
    looks_like_admin_surface as looks_like_admin_surface,
    looks_like_cloud_app_config as looks_like_cloud_app_config,
    looks_like_dependency_manifest as looks_like_dependency_manifest,
    looks_like_exposed_backup_artifact as looks_like_exposed_backup_artifact,
    looks_like_sensitive_config as looks_like_sensitive_config,
    looks_like_source_map as looks_like_source_map,
    looks_like_vcs_metadata as looks_like_vcs_metadata,
)


__all__ = [
    "artifact_path_finding_details",
    "exact_path_finding_details",
    "finding_for_path",
    "is_interesting_path",
    "origin_for_observed_path",
    "path_evidence",
    "path_finding_details",
]


def finding_for_path(observed: object) -> dict[str, object] | None:
    """Compatibility wrapper for finding payload construction."""
    from .http_path_finding_payloads import finding_for_path as implementation

    return implementation(observed)  # type: ignore[arg-type]


def path_finding_details(path: str, observed: object) -> object:
    """Compatibility wrapper for normalized path finding details."""
    from .http_path_finding_payloads import path_finding_details as implementation

    return implementation(path, observed)  # type: ignore[arg-type]


def exact_path_finding_details(path: str) -> object:
    """Compatibility wrapper for exact-path finding details."""
    from .http_path_finding_payloads import exact_path_finding_details as implementation

    return implementation(path)


def artifact_path_finding_details(
    path: str,
    origin_scope: dict[str, str],
    cwe_538: dict[str, list[str]],
) -> object:
    """Compatibility wrapper for artifact-like path finding details."""
    from .http_path_finding_payloads import artifact_path_finding_details as implementation

    return implementation(path, origin_scope, cwe_538)


def origin_for_observed_path(observed: object) -> str:
    """Compatibility wrapper for web-origin extraction."""
    from .http_path_finding_payloads import origin_for_observed_path as implementation

    return implementation(observed)  # type: ignore[arg-type]


def path_evidence(observed: object) -> str:
    """Compatibility wrapper for operator-facing path evidence."""
    from .http_path_finding_payloads import path_evidence as implementation

    return implementation(observed)  # type: ignore[arg-type]


def __getattr__(name: str) -> object:
    """Lazily preserve the old `PathFindingDetails` import location."""
    if name == "PathFindingDetails":
        from .http_path_finding_payloads import PathFindingDetails

        return PathFindingDetails
    raise AttributeError(name)
