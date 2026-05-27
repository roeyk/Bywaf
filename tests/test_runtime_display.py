"""Tests for runtime display behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

import unittest

from bywaf.runtime_display import display_runtime_serial, format_runtime_timestamp


class RuntimeDisplayTests(unittest.TestCase):
    def test_format_runtime_timestamp_shows_time_and_utc(self):
        self.assertEqual(format_runtime_timestamp("2026-05-18T12:34:56+00:00"), "12:34:56 UTC")

    def test_format_runtime_timestamp_shows_time_and_offset_timezone(self):
        self.assertEqual(format_runtime_timestamp("2026-05-18T08:34:56-04:00"), "08:34:56 UTC-04:00")

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


if __name__ == "__main__":
    unittest.main()
