"""Shared SQLite support helpers for the event store.

Provides SQLCipher loading, encryption/export helpers, process checks, serial
generation, and trusted SQL snippets used by the EventStore mixins.

Used by:
- db: configure encrypted SQLite connections and expose public helpers.
- db_* mixins: share constants and helper routines without import cycles."""

from __future__ import annotations

import os
import secrets
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
CROCKFORD_BASE32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
SERIAL_RANDOM_BITS = 128
SERIAL_BODY_LENGTH = 26
SERIAL_DISPLAY_LENGTH = 8

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


def crockford_base32(value: int, *, length: int = SERIAL_BODY_LENGTH) -> str:
    """Encode a positive integer as fixed-width Crockford Base32 text."""
    chars: list[str] = []
    for _ in range(length):
        value, remainder = divmod(value, 32)
        chars.append(CROCKFORD_BASE32_ALPHABET[remainder])
    return "".join(reversed(chars))


def new_serial(prefix: str) -> str:
    """Return a durable Crockford Base32 serial for auditable entities."""
    safe_prefix = "".join(char if char.isalnum() else "-" for char in prefix).strip("-")
    body = crockford_base32(secrets.randbits(SERIAL_RANDOM_BITS))
    return f"{safe_prefix}-{body}"


def normalize_serial_lookup(value: str) -> str:
    """Normalize operator-entered serial text for case-insensitive lookup."""
    # Crockford Base32 intentionally avoids I/L/O.  Accepting those common
    # transcription mistakes keeps short serial lookup forgiving without
    # changing the canonical stored serial.
    return value.upper().replace("I", "1").replace("L", "1").replace("O", "0")


def serial_body(value: str) -> str:
    """Return the identifier portion after a serial prefix."""
    return value.split("-", 1)[1] if "-" in value else value


def serial_matches(stored: str, query: str) -> bool:
    """Return whether `query` uniquely names or prefixes `stored`."""
    stored_normal = normalize_serial_lookup(stored)
    query_normal = normalize_serial_lookup(query)
    if stored_normal == query_normal:
        return True
    if "-" in query_normal:
        return stored_normal.startswith(query_normal)
    return serial_body(stored_normal).startswith(query_normal)


def resolve_serial_match(query: str, values: list[str] | set[str] | tuple[str, ...]) -> str | None:
    """Resolve a serial query against known serials, rejecting ambiguity."""
    matches = sorted({value for value in values if serial_matches(value, query)})
    if not matches:
        return None
    if len(matches) > 1:
        raise ValueError(f"ambiguous serial prefix: {query}")
    return matches[0]


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
