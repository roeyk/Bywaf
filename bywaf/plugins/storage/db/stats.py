"""Database statistics formatting for the storage DB commandlet.

Used by:
- storage commandlets and operator workflows that create, inspect, or switch runtime databases.
- tests that verify database lifecycle behavior.
"""

from __future__ import annotations

import re

from bywaf.artifacts import ArtifactStore, artifact_db_path
from bywaf.db import EventStore
from bywaf.plugin import CommandContext

from .paths import database_related_paths

SQL_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def format_database_stats(context: CommandContext) -> str:
    """Return a human-readable database statistics report."""
    db = context.require_db()
    mode = "encrypted" if db.encrypted else "plaintext"
    lines = [
        "Database statistics",
        f"  path: {db.path}",
        f"  mode: {mode}",
        "",
        "Main database files",
        *[f"  {path.name}: {format_bytes(path.stat().st_size)}" for path in database_related_paths(db.path)],
        "",
        "Main database tables",
        *format_count_rows(main_table_counts(db)),
        "",
        "Events by topic",
        *format_count_rows(event_topic_counts(db), empty="  none"),
        "",
        "Jobs by status",
        *format_count_rows(grouped_count(db, "jobs", "status"), empty="  none"),
        "",
        "Runtime entities",
        *format_count_rows(grouped_count(db, "runtime_entities", "entity_type"), empty="  none"),
        "",
        "Artifacts",
        *format_artifact_stats(db),
    ]
    return "\n".join(lines)


def main_table_counts(db: EventStore) -> list[tuple[str, int]]:
    """Return row counts for all non-internal main DB tables."""
    with db.connect() as conn:
        rows = conn.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name NOT LIKE 'sqlite_%'
            ORDER BY name
            """
        ).fetchall()
        counts = []
        for row in rows:
            name = str(row["name"] if hasattr(row, "keys") else row[0])
            table_name = quote_identifier(name)
            query = f"SELECT COUNT(*) FROM {table_name}"  # nosec B608
            count = conn.execute(query).fetchone()
            counts.append((name, int(count[0]) if count is not None else 0))
        return counts


def event_topic_counts(db: EventStore) -> list[tuple[str, int]]:
    """Return event counts grouped by topic."""
    with db.connect() as conn:
        rows = conn.execute("SELECT topic, COUNT(*) AS count FROM events GROUP BY topic ORDER BY count DESC, topic ASC").fetchall()
    return [(str(row["topic"]), int(row["count"])) for row in rows]


def grouped_count(db: EventStore, table: str, column: str) -> list[tuple[str, int]]:
    """Return grouped counts for trusted schema table/column names."""
    table_name = quote_identifier(table)
    column_name = quote_identifier(column)
    with db.connect() as conn:
        query = (
            f"SELECT {column_name} AS value, COUNT(*) AS count "
            f"FROM {table_name} GROUP BY {column_name} ORDER BY count DESC, value ASC"  # nosec B608
        )
        rows = conn.execute(query).fetchall()
    return [(str(row["value"] if row["value"] is not None else ""), int(row["count"])) for row in rows]


def quote_identifier(value: str) -> str:
    """Return a SQLite identifier after strict schema-name validation."""
    if not SQL_IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"invalid SQL identifier: {value!r}")
    return f'"{value}"'


def format_artifact_stats(db: EventStore) -> list[str]:
    """Return artifact DB size and row-count lines."""
    path = artifact_db_path(db.path)
    related = database_related_paths(path)
    if not related:
        return [f"  path: {path}", "  files: none", "  artifacts: 0"]
    lines = [f"  path: {path}", "  files:"]
    lines.extend(f"    {file_path.name}: {format_bytes(file_path.stat().st_size)}" for file_path in related)
    store = ArtifactStore(path, passphrase=db.passphrase)
    with store.connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()
        size = conn.execute("SELECT COALESCE(SUM(size), 0) FROM artifacts").fetchone()
        content_types = conn.execute(
            "SELECT content_type, COUNT(*) AS count FROM artifacts GROUP BY content_type ORDER BY count DESC, content_type ASC"
        ).fetchall()
        commandlets = conn.execute(
            "SELECT commandlet, COUNT(*) AS count FROM artifacts GROUP BY commandlet ORDER BY count DESC, commandlet ASC"
        ).fetchall()
    lines.append(f"  artifacts: {int(total[0]) if total is not None else 0}")
    lines.append(f"  body bytes: {format_bytes(int(size[0]) if size is not None else 0)}")
    lines.append("  content types:")
    lines.extend(format_count_rows([(str(row["content_type"]), int(row["count"])) for row in content_types], indent="    ", empty="    none"))
    lines.append("  producing commandlets:")
    lines.extend(
        format_count_rows(
            [(str(row["commandlet"] or "(none)"), int(row["count"])) for row in commandlets],
            indent="    ",
            empty="    none",
        )
    )
    return lines


def format_count_rows(rows: list[tuple[str, int]], *, indent: str = "  ", empty: str = "  none") -> list[str]:
    """Format name/count rows with aligned counts."""
    if not rows:
        return [empty]
    width = max(len(name) for name, _count in rows)
    return [f"{indent}{name:<{width}}  {count}" for name, count in rows]


def format_bytes(size: int) -> str:
    """Return a compact byte-size string."""
    units = ("B", "KiB", "MiB", "GiB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} {units[-1]}"
