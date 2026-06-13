"""Tests for runtime display behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples.

Coverage focus: runtime display regression behavior.
"""

from datetime import datetime
import unittest

from bywaf.runtime.display import display_runtime_serial, format_runtime_timestamp, render_table
from bywaf.time_format import COMPACT_RUNTIME_TS_FORMAT


class RuntimeDisplayTests(unittest.TestCase):
    """Groups regression coverage for runtime display behavior."""
    def test_format_runtime_timestamp_shows_operator_local_time(self):
        """Protect format runtime timestamp shows operator local time behavior from regressions."""
        self.assertEqual(
            format_runtime_timestamp("2026-05-18T12:34:56+00:00"),
            expected_local_runtime_timestamp("2026-05-18T12:34:56+00:00"),
        )

    def test_format_runtime_timestamp_converts_offset_timezone(self):
        """Protect format runtime timestamp converts offset timezone behavior from regressions."""
        self.assertEqual(
            format_runtime_timestamp("2026-05-18T08:34:56-04:00"),
            expected_local_runtime_timestamp("2026-05-18T08:34:56-04:00"),
        )

    def test_format_runtime_timestamp_handles_missing_value(self):
        """Protect format runtime timestamp handles missing value behavior from regressions."""
        self.assertEqual(format_runtime_timestamp(None), "unknown")

    def test_format_runtime_timestamp_leaves_malformed_value_visible(self):
        """Protect format runtime timestamp leaves malformed value visible behavior from regressions."""
        self.assertEqual(format_runtime_timestamp("not-a-time"), "not-a-time")

    def test_display_runtime_serial_strips_noisy_runtime_prefixes(self):
        """Protect display runtime serial strips noisy runtime prefixes behavior from regressions."""
        self.assertEqual(display_runtime_serial("pipeline-0123456789ABCDEFGHJKMNPQRST"), "01234567")
        self.assertEqual(display_runtime_serial("run-0123456789ABCDEFGHJKMNPQRST"), "01234567")
        self.assertEqual(display_runtime_serial("job-0123456789ABCDEFGHJKMNPQRST"), "01234567")

    def test_display_runtime_serial_keeps_commandlet_prefixed_runs(self):
        """Protect display runtime serial keeps commandlet prefixed runs behavior from regressions."""
        self.assertEqual(display_runtime_serial("hostscanner-abc123"), "hostscanner-abc123")

    def test_render_table_styles_subject_cells_after_alignment(self):
        """Protect render table styles subject cells after alignment behavior from regressions."""
        rendered = render_table(
            ("JOB", "SERIAL"),
            ((1, "ABC12345"),),
            cell_subjects=("job", "serial"),
            style_getter=lambda key, default="": {"display/style.serial": "cyan"}.get(key, default),
        )

        self.assertIn("1    \x1b[36mABC12345", rendered)

    def test_render_table_truncates_to_max_width(self):
        """Protect render table truncates to max width behavior from regressions."""
        rendered = render_table(("ID", "COMMAND"), ((1, "x" * 80),), max_width=24)

        self.assertTrue(all(len(line) <= 24 for line in rendered.splitlines()))
        self.assertIn("…", rendered)

    def test_render_table_applies_header_index_and_body_styles(self):
        """Protect render table applies header index and body styles behavior from regressions."""
        rendered = render_table(
            ("ID", "VALUE"),
            ((1, "plain"),),
            style_getter=lambda key, default="": {
                "display/style.table.header": "bold white",
                "display/style.table.index": "cyan",
                "display/style.table.body": "green",
            }.get(key, default),
        )

        self.assertIn("\x1b[1;37mID", rendered)
        self.assertIn("\x1b[36m1", rendered)
        self.assertIn("\x1b[32mplain", rendered)

    def test_render_table_applies_active_row_and_column_styles(self):
        """Protect render table applies active row and column styles behavior from regressions."""
        rendered = render_table(
            ("JOB", "STATUS", "COMMAND"),
            ((1, "active/running", "scan"), (2, "completed/finished", "report")),
            row_subjects=("table.active_row", ""),
            active_column_indexes=(1,),
            style_getter=lambda key, default="": {
                "display/style.table.active_row": "green",
                "display/style.table.active_column": "bold white",
            }.get(key, default),
        )

        self.assertIn("\x1b[32m1", rendered)
        self.assertIn("\x1b[1;37mactive/running", rendered)
        self.assertIn("completed/finished", rendered)
        self.assertNotIn("\x1b[1;37mcompleted/finished", rendered)
        self.assertNotIn("\x1b[32m2", rendered)


def expected_local_runtime_timestamp(value: str) -> str:
    """Test helper for expected local runtime timestamp."""
    parsed = datetime.fromisoformat(value).astimezone()
    timezone_name = parsed.tzname()
    suffix = f" {timezone_name}" if timezone_name else ""
    return f"{parsed.strftime(COMPACT_RUNTIME_TS_FORMAT)}{suffix}"


if __name__ == "__main__":
    unittest.main()
