"""Table data model and payload normalization helpers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

Align = Literal["left", "right", "center"]


@dataclass(frozen=True, slots=True)
class Column:
    """One display column in a structured table.

    This represents stable presentation metadata for one row key.
    Constructed by: commandlets, report renderers, `Table.from_rows()`, and
    `Table.from_payload()`.
    Used by: `Table`, `normalize_columns()`, and the format renderers when
    producing console, Markdown, CSV, JSONL, HTML, DOCX, or XLSX output.
    """

    key: str
    title: str | None = None
    align: Align = "left"

    @property
    def heading(self) -> str:
        """Return the visible table heading."""
        return self.title or self.key


@dataclass(frozen=True, slots=True)
class Table:
    """Structured tabular data that can be rendered in several formats.

    This represents display-ready rows independently of the final output format.
    Constructed by: runtime commandlets, reports, `Table.from_rows()`, and
    `Table.from_payload()`.
    Used by: `ContextRender.table()`, `handle_render_table_request()`, and the
    `render_*_table()` functions. `to_payload()`/`from_payload()` carry it
    across the plugin/framework event boundary.
    """

    columns: tuple[Column, ...]
    rows: tuple[Mapping[str, object], ...]
    title: str | None = None

    @classmethod
    def from_rows(
        cls,
        rows: Iterable[Mapping[str, object] | Sequence[object]],
        columns: Sequence[str | Column] | None = None,
        *,
        title: str | None = None,
    ) -> "Table":
        """Build a table from mapping rows or positional sequence rows.

        Called by: commandlets and reports that have row data but do not need to
        manually construct `Column` objects.
        """
        normalized_rows = tuple(rows)
        normalized_columns = normalize_columns(columns, normalized_rows)
        mapped_rows = tuple(map_row(row, normalized_columns) for row in normalized_rows)
        return cls(normalized_columns, mapped_rows, title=title)

    def to_payload(self) -> dict[str, object]:
        """Return a JSON-safe payload for framework request events.

        Called by: `ContextRender.table()` before sending a render request
        through the event boundary.
        """
        # Tables can cross the plugin/framework boundary as events. Keep the
        # payload simple so commandlets can request rendering without importing
        # terminal-specific code.
        return {
            "title": self.title,
            "columns": [
                {"key": column.key, "title": column.title, "align": column.align}
                for column in self.columns
            ],
            "rows": [
                {key: json_safe_value(value) for key, value in row.items()}
                for row in self.rows
            ],
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> "Table":
        """Build a table from a framework request payload.

        Called by: `handle_render_table_request()` when the framework services
        a plugin render request.
        """
        # Validate and normalize column definitions first. The payload crosses
        # the plugin/framework event boundary, so this method accepts only the
        # small schema produced by to_payload() before constructing Columns.
        raw_columns = payload.get("columns", ())
        if not isinstance(raw_columns, Sequence):
            raise ValueError("table columns must be a sequence")
        columns: list[Column] = []
        for raw_column in raw_columns:
            if not isinstance(raw_column, Mapping):
                raise ValueError("table column entries must be objects")
            key = raw_column.get("key")
            if not isinstance(key, str) or not key:
                raise ValueError("table column key must be a non-empty string")
            title = raw_column.get("title")
            align = raw_column.get("align", "left")
            if title is not None and not isinstance(title, str):
                raise ValueError("table column title must be a string")
            if align not in {"left", "right", "center"}:
                raise ValueError("table column align must be left, right, or center")
            columns.append(Column(key, title, align))  # type: ignore[arg-type]
        # Rows are normalized after columns because renderers expect mappings
        # keyed by column names. Stringifying row keys prevents non-string JSON
        # object keys from leaking into the rendering layer.
        raw_rows = payload.get("rows", ())
        if not isinstance(raw_rows, Sequence):
            raise ValueError("table rows must be a sequence")
        rows: list[Mapping[str, object]] = []
        for raw_row in raw_rows:
            if not isinstance(raw_row, Mapping):
                raise ValueError("table row entries must be objects")
            rows.append({str(key): value for key, value in raw_row.items()})
        # Title is optional display metadata; validate it last so the structural
        # column/row errors remain the first failures reported to callers.
        title = payload.get("title")
        if title is not None and not isinstance(title, str):
            raise ValueError("table title must be a string")
        return cls(tuple(columns), tuple(rows), title=title)


def normalize_columns(
    columns: Sequence[str | Column] | None,
    rows: Sequence[Mapping[str, object] | Sequence[object]],
) -> tuple[Column, ...]:
    """Return normalized column metadata for rows."""
    if columns is not None:
        return tuple(column if isinstance(column, Column) else Column(str(column)) for column in columns)
    if not rows:
        return ()
    first = rows[0]
    if isinstance(first, Mapping):
        return tuple(Column(str(key)) for key in first.keys())
    return tuple(Column(str(index)) for index in range(len(first)))


def map_row(row: Mapping[str, object] | Sequence[object], columns: Sequence[Column]) -> Mapping[str, object]:
    """Return a mapping row keyed by normalized column names."""
    if isinstance(row, Mapping):
        return {column.key: row.get(column.key, "") for column in columns}
    return {
        column.key: row[index] if index < len(row) else ""
        for index, column in enumerate(columns)
    }


def json_safe_value(value: object) -> object:
    """Return a value safe for JSON event payloads."""
    if value is None or isinstance(value, str | int | float | bool):
        return value
    return str(value)


def table_values(table: Table) -> list[list[str]]:
    """Return display values for a table."""
    return [
        [value_to_text(row.get(column.key, "")) for column in table.columns]
        for row in table.rows
    ]


def value_to_text(value: object) -> str:
    """Return a compact display string for one table cell."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)
