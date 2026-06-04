"""Tests for SQLite contention benchmark helpers."""

from pathlib import Path
import tempfile
import unittest

from bywaf.tools.sqlite_contention_benchmark import (
    WorkerResult,
    aggregate_results,
    run_benchmark,
)


class SQLiteContentionBenchmarkTests(unittest.TestCase):
    def test_aggregate_results_counts_failures_and_latency(self):
        result = aggregate_results(
            Path("bench.sqlite3"),
            (
                WorkerResult(0, 2, 2, 0, 0, 0.2, (1.0, 3.0), (2.0,), ()),
                WorkerResult(1, 2, 1, 1, 1, 0.3, (4.0,), (), ("database is locked",)),
            ),
            writers=2,
            events_per_writer=2,
            payload_bytes=16,
            read_every=1,
            elapsed_seconds=0.5,
        )

        self.assertEqual(result.attempted, 4)
        self.assertEqual(result.published, 3)
        self.assertEqual(result.failures, 1)
        self.assertEqual(result.locked_failures, 1)
        self.assertEqual(result.throughput_events_per_second, 6)
        self.assertEqual(result.write_latency_ms["count"], 3)
        self.assertEqual(result.write_latency_ms["p50"], 3.0)

    def test_tiny_benchmark_exercises_event_store_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_benchmark(
                Path(tmp, "bench.sqlite3"),
                writers=1,
                events_per_writer=3,
                payload_bytes=8,
                read_every=1,
            )

        self.assertEqual(result.attempted, 3)
        self.assertEqual(result.published, 3)
        self.assertEqual(result.failures, 0)
        self.assertEqual(result.write_latency_ms["count"], 3)
        self.assertEqual(result.read_latency_ms["count"], 3)


if __name__ == "__main__":
    unittest.main()
