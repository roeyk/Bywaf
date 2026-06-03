"""HTTP path finding classification helpers."""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass

from bywaf.event.schema_objects import HttpPathObserved
from bywaf.finding import candidate_payload

ADMIN_PATHS = frozenset({"/admin/", "/admin", "/login", "/wp-login.php"})
ADMIN_KEYWORDS = ("admin", "administrator", "login", "sign in", "wp-login")
BACKUP_ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".7z", ".rar")
DATABASE_DUMP_SUFFIXES = (".sql", ".sql.gz", ".dump")
ARCHIVE_CONTENT_TYPES = (
    "application/gzip",
    "application/octet-stream",
    "application/x-7z-compressed",
    "application/x-gzip",
    "application/x-rar-compressed",
    "application/x-tar",
    "application/x-zip-compressed",
    "application/zip",
)
SQL_DUMP_MARKERS = ("create table", "insert into", "dump completed", "mysqldump", "postgresql database dump")
VCS_METADATA_PATHS = frozenset({"/.svn/entries", "/.hg/hgrc", "/.bzr/branch/branch.conf"})
SOURCE_MAP_SUFFIX = ".map"
DEPENDENCY_MANIFEST_PATHS = frozenset(
    {
        "/composer.lock",
        "/gemfile.lock",
        "/package-lock.json",
        "/pipfile.lock",
        "/pnpm-lock.yaml",
        "/poetry.lock",
        "/yarn.lock",
    }
)
DEPENDENCY_MANIFEST_MARKERS = {
    "/package-lock.json": (('"lockfileversion"',), ('"packages"', '"dependencies"')),
    "/composer.lock": (('"content-hash"',), ('"packages"',)),
    "/poetry.lock": (("[[package]]",), ("name =",), ("version =",)),
    "/pipfile.lock": (('"_meta"',), ('"default"',)),
    "/gemfile.lock": (("gem\n",), ("dependencies\n",)),
    "/yarn.lock": (("# yarn lockfile", "__metadata:"),),
    "/pnpm-lock.yaml": (("lockfileversion:",), ("packages:",)),
}
SENSITIVE_CONFIG_PATHS = frozenset(
    {
        "/.npmrc",
        "/.pypirc",
        "/config.php",
        "/config.yml",
        "/settings.py",
        "/wp-config.php",
    }
)
SENSITIVE_CONFIG_MARKERS = (
    "_authtoken",
    "api_key",
    "api-key",
    "auth_token",
    "database_url",
    "db_password",
    "secret_key",
    "password =",
    "password:",
    "password=",
)


@dataclass(frozen=True, slots=True)
class PathFindingDetails:
    """Static normalized finding fields for one HTTP path observation."""

    title: str
    finding_class: str
    severity: str
    target_scope: dict[str, str] | None = None
    identifiers: dict[str, list[str]] | None = None
    recommendation: str = ""


GIT_CONFIG_RECOMMENDATION = (
    "Remove the .git directory from deployed web roots and block access to source-control metadata paths."
)
SOURCE_CONTROL_METADATA_RECOMMENDATION = (
    "Remove source-control metadata from deployed web roots and block access to revision-control metadata paths."
)
SOURCE_MAP_RECOMMENDATION = (
    "Publish production assets without source maps, or restrict source-map access to authorized debugging workflows."
)
DEPENDENCY_METADATA_RECOMMENDATION = (
    "Remove dependency manifests and lockfiles from deployed web roots, or restrict access to build metadata."
)
SENSITIVE_CONFIG_RECOMMENDATION = (
    "Remove sensitive configuration files from deployed web roots and rotate any exposed credentials."
)


def is_interesting_path(path: str, result: dict[str, object]) -> bool:
    """Return whether a response should be highlighted."""
    status = result.get("status")
    if not isinstance(status, int) or status >= 400:
        return False
    lowered = path.casefold()
    sample = str(result.get("sample") or "").casefold()
    title = str(result.get("title") or "").casefold()
    content_type = str(result.get("content_type") or "").casefold()
    return (
        lowered in {"/.git/config", "/server-status", "/.env", "/actuator/env"}
        or (lowered in ADMIN_PATHS and looks_like_admin_surface(title, sample))
        or looks_like_exposed_backup_artifact(lowered, content_type, sample)
        or looks_like_source_map(lowered, sample)
        or looks_like_vcs_metadata(lowered, sample)
        or looks_like_dependency_manifest(lowered, sample)
        or looks_like_sensitive_config(lowered, sample)
        or "repositoryformatversion" in sample
        or "spring.cloud" in sample
        or "database_url" in sample
    )


def looks_like_admin_surface(title: str, sample: str) -> bool:
    """Return whether response text looks like a login or admin surface."""
    evidence = f"{title} {sample}"
    return any(keyword in evidence for keyword in ADMIN_KEYWORDS)


def looks_like_exposed_backup_artifact(path: str, content_type: str, sample: str) -> bool:
    """Return whether response metadata looks like a downloadable backup artifact."""
    return (
        is_backup_archive_path(path) and any(content_type.startswith(item) for item in ARCHIVE_CONTENT_TYPES)
    ) or (is_database_dump_path(path) and any(marker in sample for marker in SQL_DUMP_MARKERS))


def looks_like_source_map(path: str, sample: str) -> bool:
    """Return whether response text looks like an exposed JavaScript source map."""
    return (
        path.endswith(SOURCE_MAP_SUFFIX)
        and '"version"' in sample
        and '"sources"' in sample
        and '"mappings"' in sample
    )


def looks_like_vcs_metadata(path: str, sample: str) -> bool:
    """Return whether response text looks like legacy source-control metadata."""
    if path == "/.svn/entries":
        return "wc-entries" in sample or "\ndir\n" in sample or "committed-rev" in sample
    if path == "/.hg/hgrc":
        return "[paths]" in sample or "[ui]" in sample
    if path == "/.bzr/branch/branch.conf":
        return "[branch]" in sample
    return False


def looks_like_dependency_manifest(path: str, sample: str) -> bool:
    """Return whether response text looks like exposed dependency metadata."""
    marker_groups = DEPENDENCY_MANIFEST_MARKERS.get(path)
    return bool(marker_groups) and all(any(marker in sample for marker in group) for group in marker_groups)


def looks_like_sensitive_config(path: str, sample: str) -> bool:
    """Return whether response text looks like an exposed sensitive config file."""
    return path in SENSITIVE_CONFIG_PATHS and any(marker in sample for marker in SENSITIVE_CONFIG_MARKERS)


def is_backup_archive_path(path: str) -> bool:
    """Return whether the path name looks like a backup/archive artifact."""
    return path.endswith(BACKUP_ARCHIVE_SUFFIXES)


def is_database_dump_path(path: str) -> bool:
    """Return whether the path name looks like a database dump artifact."""
    return path.endswith(DATABASE_DUMP_SUFFIXES)


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
            SOURCE_CONTROL_METADATA_RECOMMENDATION,
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
            DEPENDENCY_METADATA_RECOMMENDATION,
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
