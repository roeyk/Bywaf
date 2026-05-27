"""Tests for runtime display behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

import unittest

from bywaf.runtime_display import display_runtime_serial, format_runtime_timestamp, render_table


class RuntimeDisplayTests(unittest.TestCase):
    def test_format_runtime_timestamp_shows_time_and_utc(self):
        self.assertEqual(format_runtime_timestamp("2026-05-18T12:34:56+00:00"), "2026-05-18 12:34:56 UTC")

    def test_format_runtime_timestamp_shows_time_and_offset_timezone(self):
        self.assertEqual(format_runtime_timestamp("2026-05-18T08:34:56-04:00"), "2026-05-18 08:34:56 UTC-04:00")

    def test_format_runtime_timestamp_handles_missing_value(self):
        self.assertEqual(format_runtime_timestamp(None), "unknown")

    def test_format_runtime_timestamp_leaves_malformed_value_visible(self):
        self.assertEqual(format_runtime_timestamp("not-a-time"), "not-a-time")

    def test_display_runtime_serial_strips_noisy_runtime_prefixes(self):
        self.assertEqual(display_runtime_serial("pipeline-0123456789ABCDEFGHJKMNPQRST"), "01234567")
        self.assertEqual(display_runtime_serial("run-0123456789ABCDEFGHJKMNPQRST"), "01234567")
        self.assertEqual(display_runtime_serial("job-0123456789ABCDEFGHJKMNPQRST"), "01234567")

    def test_display_runtime_serial_keeps_commandlet_prefixed_runs(self):
        self.assertEqual(display_runtime_serial("hostscanner-abc123"), "hostscanner-abc123")

    def test_render_table_styles_subject_cells_after_alignment(self):
        rendered = render_table(
            ("JOB", "SERIAL"),
            ((1, "ABC12345"),),
            cell_subjects=("job", "serial"),
            style_getter=lambda key, default="": {"display/style.serial": "cyan"}.get(key, default),
        )

        self.assertIn("1    \x1b[36mABC12345", rendered)

    def test_render_table_truncates_to_max_width(self):
        rendered = render_table(("ID", "COMMAND"), ((1, "x" * 80),), max_width=24)

        self.assertTrue(all(len(line) <= 24 for line in rendered.splitlines()))
        self.assertIn("…", rendered)

    def test_render_table_applies_header_index_and_body_styles(self):
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


if __name__ == "__main__":
    unittest.main()
