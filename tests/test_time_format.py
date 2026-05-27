"""Tests for shared timestamp formatting helpers.

Provides coverage for the common operator and runtime timestamp policies used
across REPL, audit, notes, and runtime listings.

Used by:
- pytest and CI: detect formatting drift across user-facing commands.
- maintainers: document the canonical timestamp shapes."""

from datetime import datetime, timezone
import unittest

from bywaf.time_format import (
    format_compact_runtime_timestamp,
    format_duration_between,
    format_operator_timestamp,
    normalize_history_timestamp_for_display,
)


class TimeFormatTests(unittest.TestCase):
    def test_format_operator_timestamp_uses_date_time_timezone_order(self):
        text = format_operator_timestamp(datetime(2026, 5, 22, 12, 28, 32, tzinfo=timezone.utc))
        self.assertRegex(text, r"20260522 \d{2}:\d{2}:\d{2} [A-Z]+")

    def test_format_compact_runtime_timestamp_preserves_source_timezone(self):
        self.assertEqual(format_compact_runtime_timestamp("2026-05-18T12:34:56+00:00"), "20260518 12:34:56 UTC")
        self.assertEqual(format_compact_runtime_timestamp("2026-05-18T08:34:56-04:00"), "20260518 08:34:56 UTC-04:00")

    def test_format_duration_between_formats_human_runtime_duration(self):
        self.assertEqual(
            format_duration_between("2026-05-18T12:00:00+00:00", "2026-05-18T13:05:00+00:00"),
            "1h 5m",
        )
        self.assertEqual(format_duration_between("2026-05-18T12:00:00+00:00", None), "ongoing")

    def test_format_compact_runtime_timestamp_handles_missing_and_malformed_values(self):
        self.assertEqual(format_compact_runtime_timestamp(None), "unknown")
        self.assertEqual(format_compact_runtime_timestamp("not-a-time"), "not-a-time")

    def test_normalize_history_timestamp_moves_timezone_after_time(self):
        self.assertEqual(
            normalize_history_timestamp_for_display("2026-05-17 EDT 10:00:00"),
            "20260517 10:00:00 EDT",
        )
        self.assertEqual(
            normalize_history_timestamp_for_display("2026-05-17 10:00:00 EDT"),
            "20260517 10:00:00 EDT",
        )


if __name__ == "__main__":
    unittest.main()
