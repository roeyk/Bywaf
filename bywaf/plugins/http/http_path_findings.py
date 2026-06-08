"""HTTP path finding classification helpers."""

from __future__ import annotations

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
CLOUD_APP_CONFIG_PATHS = frozenset(
    {
        "/.aws/credentials",
        "/application.yaml",
        "/application.yml",
        "/appsettings.json",
        "/firebase.json",
    }
)
CLOUD_APP_CONFIG_MARKER_GROUPS = {
    "/.aws/credentials": (("[default]", "[profile "), ("aws_access_key_id",), ("aws_secret_access_key",)),
    "/application.yaml": (("spring:", "server:", "datasource:", "database:"), ("password:", "url:", "username:")),
    "/application.yml": (("spring:", "server:", "datasource:", "database:"), ("password:", "url:", "username:")),
    "/appsettings.json": (('"connectionstrings"', '"logging"', '"allowedhosts"'), ('"password"', '"defaultconnection"', '"apikey"')),
    "/firebase.json": (('"hosting"', '"firestore"', '"functions"'), ('"public"', '"rules"', '"source"')),
}


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
        or looks_like_cloud_app_config(lowered, sample)
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


def looks_like_cloud_app_config(path: str, sample: str) -> bool:
    """Return whether response text looks like exposed cloud or app config."""
    marker_groups = CLOUD_APP_CONFIG_MARKER_GROUPS.get(path)
    return bool(marker_groups) and all(any(marker in sample for marker in group) for group in marker_groups)


def is_backup_archive_path(path: str) -> bool:
    """Return whether the path name looks like a backup/archive artifact."""
    return path.endswith(BACKUP_ARCHIVE_SUFFIXES)


def is_database_dump_path(path: str) -> bool:
    """Return whether the path name looks like a database dump artifact."""
    return path.endswith(DATABASE_DUMP_SUFFIXES)


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
