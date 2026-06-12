"""Tests for SQLite contention benchmark helpers.

Coverage focus: sqlite contention benchmark regression behavior.
"""

from pathlib import Path
import tempfile
import unittest

from bywaf.tools.sqlite.contention_benchmark import (
    PLUGIN_WORKLOAD,
    WorkerResult,
    aggregate_results,
    run_benchmark,
)


class SQLiteContentionBenchmarkTests(unittest.TestCase):
    """Groups regression coverage for sQLite contention benchmark helpers."""
    def test_aggregate_results_counts_failures_and_latency(self):
        """Protect aggregate results counts failures and latency behavior from regressions."""
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
        self.assertEqual(result.workload, "direct")
        self.assertEqual(result.published, 3)
        self.assertEqual(result.failures, 1)
        self.assertEqual(result.locked_failures, 1)
        self.assertEqual(result.throughput_events_per_second, 6)
        self.assertEqual(result.write_latency_ms["count"], 3)
        self.assertEqual(result.write_latency_ms["p50"], 3.0)

    def test_tiny_benchmark_exercises_event_store_path(self):
        """Protect tiny benchmark exercises event store path behavior from regressions."""
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

    def test_tiny_plugin_workload_exercises_context_event_path(self):
        """Protect tiny plugin workload exercises context event path behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp, "bench.sqlite3")
            result = run_benchmark(
                database,
                writers=1,
                events_per_writer=3,
                payload_bytes=8,
                read_every=1,
                workload=PLUGIN_WORKLOAD,
            )

        self.assertEqual(result.workload, PLUGIN_WORKLOAD)
        self.assertEqual(result.attempted, 3)
        self.assertEqual(result.published, 3)
        self.assertEqual(result.failures, 0)
        self.assertEqual(result.write_latency_ms["count"], 3)


if __name__ == "__main__":
    unittest.main()
