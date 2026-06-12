"""Tests for rendering behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples.

Coverage focus: rendering regression behavior.
"""

import contextlib
import io
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from typing import cast
from unittest.mock import patch

from bywaf.app import ShellState, make_runner, process_framework_requests
from bywaf.plugin import CommandContext
from bywaf.rendering import Column, Table, render_table


class RenderingTests(unittest.TestCase):
    """Groups regression coverage for rendering behavior."""
    def test_table_from_mapping_rows_infers_columns(self):
        """Protect table from mapping rows infers columns behavior from regressions."""
        table = Table.from_rows(({"host": "127.0.0.1", "port": 80},))
        self.assertEqual(tuple(column.key for column in table.columns), ("host", "port"))
        self.assertEqual(table.rows[0]["host"], "127.0.0.1")

    def test_table_from_sequence_rows_uses_columns(self):
        """Protect table from sequence rows uses columns behavior from regressions."""
        table = Table.from_rows((("127.0.0.1", 80),), ("host", "port"))
        self.assertEqual(table.rows[0], {"host": "127.0.0.1", "port": 80})

    def test_console_renderer_uses_titles_and_alignment(self):
        """Protect console renderer uses titles and alignment behavior from regressions."""
        table = Table.from_rows(
            ({"host": "127.0.0.1", "port": 80},),
            (Column("host", "Host"), Column("port", "Port", "right")),
            title="Open ports",
        )
        rendered = render_table(table, "console")
        self.assertIn("Open ports", rendered)
        self.assertIn("Host       ", rendered)
        self.assertIn("Port", rendered)

    def test_console_renderer_truncates_to_terminal_width(self):
        """Protect console renderer truncates to terminal width behavior from regressions."""
        table = Table.from_rows(
            ({"id": "1", "description": "x" * 80},),
            (Column("id", "ID"), Column("description", "Description")),
        )
        with patch("bywaf.runtime_table_widths.shutil.get_terminal_size", return_value=os.terminal_size((24, 24))):
            rendered = render_table(table, "console")

        self.assertTrue(all(len(line) <= 24 for line in rendered.splitlines()))
        self.assertIn("…", rendered)

    def test_console_renderer_applies_table_styles(self):
        table = Table.from_rows(({"id": "1", "value": "plain"},), ("id", "value"))
        rendered = render_table(table, "console")
        self.assertNotIn("\x1b[", rendered)

        from bywaf.rendering import render_console_table

        styled = render_console_table(
            table,
            lambda key, default="": {
                "display/style.table.header": "bold white",
                "display/style.table.index": "cyan",
                "display/style.table.body": "green",
            }.get(key, default),
        )
        self.assertIn("\x1b[1;37mid", styled)
        self.assertIn("\x1b[36m1", styled)
        self.assertIn("\x1b[32mplain", styled)

    def test_markdown_renderer_escapes_pipes(self):
        table = Table.from_rows(({"name": "a|b"},), ("name",))
        self.assertIn("a\\|b", render_table(table, "md"))

    def test_csv_renderer_outputs_header_and_rows(self):
        table = Table.from_rows(({"host": "127.0.0.1", "port": 80},), ("host", "port"))
        self.assertEqual(render_table(table, "csv"), "host,port\r\n127.0.0.1,80\r\n")

    def test_jsonl_renderer_outputs_rows(self):
        table = Table.from_rows(({"host": "127.0.0.1", "port": 80},), ("host", "port"))
        self.assertEqual(render_table(table, "jsonl"), '{"host": "127.0.0.1", "port": 80}')

    def test_html_renderer_escapes_cells(self):
        table = Table.from_rows(({"value": "<script>"},), ("value",))
        self.assertIn("&lt;script&gt;", render_table(table, "html"))

    def test_docx_renderer_returns_bytes_when_dependency_available(self):
        if importlib.util.find_spec("docx") is None:
            self.skipTest("python-docx is not installed")
        table = Table.from_rows(({"host": "127.0.0.1"},), ("host",))
        rendered = render_table(table, "docx")
        self.assertIsInstance(rendered, bytes)
        self.assertTrue(cast(bytes, rendered).startswith(b"PK"))

    def test_xlsx_renderer_returns_bytes_when_dependency_available(self):
        if importlib.util.find_spec("openpyxl") is None:
            self.skipTest("openpyxl is not installed")
        table = Table.from_rows(({"host": "127.0.0.1"},), ("host",))
        rendered = render_table(table, "xlsx")
        self.assertIsInstance(rendered, bytes)
        self.assertTrue(cast(bytes, rendered).startswith(b"PK"))

    def test_context_render_table_requests_framework_rendering(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(
                runner.db,
                source="plugin",
                metadata={"capabilities": ("framework.render.table",), "command_run_id": "run-1"},
            )
            context.render.table(Table.from_rows(({"host": "127.0.0.1"},), ("host",)))
            request = runner.db.events_for_topic("framework.render.table.requested")[0]
            self.assertEqual(request.payload["row_count"], 1)
            used = runner.db.events_for_topic("plugin.capability.used")[0]
            self.assertEqual(used.payload["capability"], "framework.render.table")
            self.assertTrue(used.payload["declared"])

    def test_framework_render_table_request_prints_and_audits(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(
                runner.db,
                source="plugin",
                metadata={"capabilities": ("framework.render.table",), "command_run_id": "run-1"},
            )
            context.render.table(Table.from_rows(({"host": "127.0.0.1"},), ("host",), title="Hosts"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                process_framework_requests(runner, ShellState())
            self.assertIn("Hosts", output.getvalue())
            self.assertIn("127.0.0.1", output.getvalue())
            rendered = runner.db.events_for_topic("render.table")[0]
            self.assertEqual(rendered.payload["format"], "console")
            self.assertEqual(rendered.payload["row_count"], 1)

    def test_compatibility_context_table_uses_rendering_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(runner.db, source="plugin", metadata={"command_run_id": "run-1"})
            context.table(({"host": "127.0.0.1"},), ("host",), title="Hosts")
            request = runner.db.events_for_topic("framework.render.table.requested")[0]
            self.assertEqual(request.payload["title"], "Hosts")


if __name__ == "__main__":
    unittest.main()
