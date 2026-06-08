"""Shared HTTP path classification constants and helpers.

Used by: `http_path_findings` for response classification and
`http_path_finding_payloads` for normalized finding metadata.
"""

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


def is_backup_archive_path(path: str) -> bool:
    """Return whether the path name looks like a backup/archive artifact."""
    return path.endswith(BACKUP_ARCHIVE_SUFFIXES)


def is_database_dump_path(path: str) -> bool:
    """Return whether the path name looks like a database dump artifact."""
    return path.endswith(DATABASE_DUMP_SUFFIXES)
