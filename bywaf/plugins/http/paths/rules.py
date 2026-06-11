"""Shared HTTP path classification constants and helpers.

Used by: `paths.findings` for response classification and
`paths.finding_payloads` for normalized finding metadata.
"""

from __future__ import annotations

from dataclasses import dataclass

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
EXACT_EXPOSURE_PATHS = frozenset({"/.git/config", "/server-status", "/.env", "/actuator/env"})
GLOBAL_SAMPLE_MARKERS = ("repositoryformatversion", "spring.cloud", "database_url")


@dataclass(frozen=True, slots=True)
class PathResponseSignals:
    """Normalized response text and metadata used by path classifiers.

    Constructed by: `response_signals()`.
    Used by: `is_interesting_path()` and `path_has_content_evidence()` so
    individual classifiers do not repeatedly unpack the raw probe dictionary.
    """

    sample: str
    title: str
    content_type: str


def is_backup_archive_path(path: str) -> bool:
    """Return whether the path name looks like a backup/archive artifact."""
    return path.endswith(BACKUP_ARCHIVE_SUFFIXES)


def is_database_dump_path(path: str) -> bool:
    """Return whether the path name looks like a database dump artifact."""
    return path.endswith(DATABASE_DUMP_SUFFIXES)


def response_signals(result: dict[str, object]) -> PathResponseSignals:
    """Return normalized classification inputs from one probe result."""
    return PathResponseSignals(
        sample=str(result.get("sample") or "").casefold(),
        title=str(result.get("title") or "").casefold(),
        content_type=str(result.get("content_type") or "").casefold(),
    )


def response_status_is_reviewable(result: dict[str, object]) -> bool:
    """Return whether a probe status is eligible for finding classification."""
    status = result.get("status")
    return isinstance(status, int) and status < 400


def is_interesting_path(path: str, result: dict[str, object]) -> bool:
    """Return whether a path probe response should be promoted for review.

    Called by: `http_paths.http_paths()` through the facade in
    `paths.findings`.
    """
    if not response_status_is_reviewable(result):
        return False
    lowered = path.casefold()
    signals = response_signals(result)
    return (
        lowered in EXACT_EXPOSURE_PATHS
        or path_has_content_evidence(lowered, signals)
        or sample_contains_global_exposure_marker(signals.sample)
    )


def path_has_content_evidence(path: str, signals: PathResponseSignals) -> bool:
    """Return whether content-specific rules confirm a candidate path hit."""
    return (
        (path in ADMIN_PATHS and looks_like_admin_surface(signals.title, signals.sample))
        or looks_like_exposed_backup_artifact(path, signals.content_type, signals.sample)
        or looks_like_source_map(path, signals.sample)
        or looks_like_vcs_metadata(path, signals.sample)
        or looks_like_dependency_manifest(path, signals.sample)
        or looks_like_sensitive_config(path, signals.sample)
        or looks_like_cloud_app_config(path, signals.sample)
    )


def sample_contains_global_exposure_marker(sample: str) -> bool:
    """Return whether generic response text contains high-signal exposure markers."""
    return any(marker in sample for marker in GLOBAL_SAMPLE_MARKERS)


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
