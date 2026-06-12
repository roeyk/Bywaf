"""Tests for SQLite query benchmark helpers."""

from pathlib import Path
import tempfile
import unittest

from bywaf.tools.sqlite_query_benchmark import (
    REPORT_CONTEXT_TOPICS,
    database_size,
    populate_database,
    run_query_benchmark,
)


class SQLiteQueryBenchmarkTests(unittest.TestCase):
    """Groups regression coverage for sQLite query benchmark helpers."""
    def test_populate_database_creates_requested_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp, "query.sqlite3")
            populate_seconds = populate_database(database, events=12, payload_bytes=8)
            result = run_query_benchmark(database, events=12, repetitions=1, payload_bytes=8)

        self.assertGreaterEqual(populate_seconds, 0)
        self.assertEqual(result.events, 12)
        self.assertGreater(result.database_bytes, 0)
        self.assertEqual({measurement.name for measurement in result.measurements} >= {"recent_25", "audit_jsonl_scan_100000"}, True)

    def test_benchmark_reuses_existing_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp, "query.sqlite3")
            first = run_query_benchmark(database, events=10, repetitions=1, payload_bytes=4)
            second = run_query_benchmark(database, events=5, repetitions=1, payload_bytes=4)

        self.assertEqual(first.events, 10)
        self.assertEqual(second.events, 10)
        self.assertEqual(second.populate_seconds, 0)
        self.assertEqual(second.maintenance_measurements, ())

    def test_benchmark_can_measure_maintenance_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp, "query.sqlite3")
            result = run_query_benchmark(database, events=10, repetitions=1, payload_bytes=4, maintenance=True)

        measurements = {measurement.name for measurement in result.maintenance_measurements}
        self.assertEqual(
            measurements,
            {"table_counts", "checkpoint", "sqlite_export_copy", "vacuum"},
        )

    def test_database_size_includes_database_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp, "query.sqlite3")
            populate_database(database, events=len(REPORT_CONTEXT_TOPICS), payload_bytes=0)

            size = database_size(database)

        self.assertGreater(size, 0)


if __name__ == "__main__":
    unittest.main()
