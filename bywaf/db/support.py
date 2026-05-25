"""Shared SQLite support helpers for the event store.

Provides SQLCipher loading, encryption/export helpers, process checks, serial
generation, and trusted SQL snippets used by the EventStore mixins.

Used by:
- db: configure encrypted SQLite connections and expose public helpers.
- db_* mixins: share constants and helper routines without import cycles."""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any

sqlcipher: Any
try:
    from sqlcipher3 import dbapi2 as sqlcipher  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - exercised on systems without the optional extra.
    sqlcipher = None

SQLITE_HEADER = b"SQLite format 3\x00"
# Keep this tuple centralized so listing, stale detection, and UI status agree
# on which jobs are still considered live.
ACTIVE_JOB_STATUSES = ("queued", "claimed", "running", "pausing", "paused", "cancelling")

def artifact_count_queries() -> dict[str, str]:
    """Return artifact count queries keyed by trusted event scope column."""
    # These snippets are selected by fixed keys, never interpolated from user
    # input, so callers can include them in larger SQL statements safely.
    return {
        "command_run_id": """
            SELECT command_run_id AS target_id,
                   COUNT(DISTINCT json_extract(payload_json, '$.artifact_id')) AS artifacts
            FROM events
            WHERE topic = 'artifact.attached'
              AND command_run_id IS NOT NULL
            GROUP BY command_run_id
        """,
        "pipeline_id": """
            SELECT pipeline_id AS target_id,
                   COUNT(DISTINCT json_extract(payload_json, '$.artifact_id')) AS artifacts
            FROM events
            WHERE topic = 'artifact.attached'
              AND pipeline_id IS NOT NULL
            GROUP BY pipeline_id
        """,
    }


def set_sqlcipher_key(conn: Any, passphrase: str) -> None:
    """Apply a SQLCipher key to a new connection.

    SQLCipher's PRAGMA syntax does not accept DB-API placeholders on all builds,
    so the passphrase is escaped as a SQL string literal before being embedded.
    """
    conn.execute(f"PRAGMA key = {sql_literal(passphrase)}")
    conn.execute("SELECT count(*) FROM sqlite_master")


def sql_literal(value: str) -> str:
    """Return `value` as a single-quoted SQL literal."""
    return "'" + value.replace("'", "''") + "'"


def database_appears_encrypted(path: Path | str) -> bool:
    """Return True when an existing DB does not have the plaintext SQLite header."""
    db_path = Path(path)
    if not db_path.exists() or db_path.stat().st_size == 0:
        return False
    with db_path.open("rb") as handle:
        return handle.read(len(SQLITE_HEADER)) != SQLITE_HEADER


def sqlcipher_available() -> bool:
    """Return whether the optional SQLCipher DB-API driver is importable."""
    return sqlcipher is not None


def process_exists(pid: int) -> bool:
    """Return whether an OS process currently exists for a recorded PID."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def new_serial(prefix: str) -> str:
    """Return a durable serial for auditable entities."""
    safe_prefix = "".join(char if char.isalnum() else "-" for char in prefix).strip("-")
    return f"{safe_prefix}-{uuid.uuid4().hex}"


def export_encrypted_database(
    source: Path | str,
    destination: Path | str,
    passphrase: str,
    *,
    source_passphrase: str | None = None,
) -> None:
    """Export a SQLite database to an encrypted SQLCipher database."""
    if sqlcipher is None:
        raise RuntimeError("encrypted database export requires the sqlcipher3-binary package")
    export_sqlcipher_database(source, destination, passphrase, source_passphrase=source_passphrase)


def export_plaintext_database(
    source: Path | str,
    destination: Path | str,
    *,
    source_passphrase: str,
) -> None:
    """Export an encrypted SQLCipher database to plaintext SQLite."""
    if sqlcipher is None:
        raise RuntimeError("plaintext database export requires the sqlcipher3-binary package")
    export_sqlcipher_database(source, destination, "", source_passphrase=source_passphrase)


def export_sqlcipher_database(
    source: Path | str,
    destination: Path | str,
    destination_passphrase: str,
    *,
    source_passphrase: str | None = None,
) -> None:
    """Export from a SQLCipher-readable source to a destination database."""
    if sqlcipher is None:
        raise RuntimeError("database export requires the sqlcipher3-binary package")
    source_path = Path(source)
    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    if destination_path.exists():
        destination_path.unlink()
    with sqlcipher.connect(str(source_path), isolation_level=None) as conn:
        if source_passphrase is not None:
            set_sqlcipher_key(conn, source_passphrase)
        # SQLCipher exports by attaching the destination and copying through
        # sqlcipher_export(); this handles encrypted->encrypted and
        # encrypted->plaintext depending on destination_passphrase.
        conn.execute(
            f"ATTACH DATABASE {sql_literal(str(destination_path))} AS exported "
            f"KEY {sql_literal(destination_passphrase)}"
        )
        conn.execute("SELECT sqlcipher_export('exported')")
        conn.execute("DETACH DATABASE exported")
