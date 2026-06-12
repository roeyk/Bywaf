"""SQLite event-store contention benchmark.

Provides a repeatable benchmark for Bywaf's current direct-write event-store
behavior under multiple process writers.

Used by:
- scripts/sqlite_contention_benchmark.py: source-checkout command wrapper.
- maintainers: collect DBQ-001/PERF-001 measurements before storage changes.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from ...db import EventStore
from ...plugin import CommandContext


BENCHMARK_TOPIC = "benchmark.event"
DIRECT_WORKLOAD = "direct"
PLUGIN_WORKLOAD = "plugin"
WORKLOADS = (DIRECT_WORKLOAD, PLUGIN_WORKLOAD)


@dataclass(frozen=True, slots=True)
class WorkerResult:
    """Measurements from one writer process.

    Constructed by: `run_writer()` inside each benchmark worker process.
    Consumed by: `aggregate_results()` for totals and by `format_result()` when
    showing per-worker sample errors.
    """

    writer: int
    attempted: int
    published: int
    failures: int
    locked_failures: int
    elapsed_seconds: float
    write_latencies_ms: tuple[float, ...]
    read_latencies_ms: tuple[float, ...]
    errors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    """Aggregated benchmark measurements.

    Constructed by: `aggregate_results()` after all writer processes complete.
    Consumed by: JSON output, human-readable CLI output, and performance docs
    when recording baseline measurements.
    """

    database: str
    workload: str
    writers: int
    events_per_writer: int
    payload_bytes: int
    read_every: int
    attempted: int
    published: int
    failures: int
    locked_failures: int
    elapsed_seconds: float
    throughput_events_per_second: float
    write_latency_ms: dict[str, float]
    read_latency_ms: dict[str, float]
    workers: tuple[WorkerResult, ...]


def run_benchmark(
    database: Path,
    *,
    writers: int,
    events_per_writer: int,
    payload_bytes: int,
    read_every: int = 0,
    workload: str = DIRECT_WORKLOAD,
) -> BenchmarkResult:
    """Run a multi-process EventStore write contention benchmark.

    Called by: `scripts/sqlite_contention_benchmark.py` and maintainers
    collecting performance baselines before storage changes.
    """
    if writers < 1:
        raise ValueError("writers must be at least 1")
    if events_per_writer < 1:
        raise ValueError("events-per-writer must be at least 1")
    if payload_bytes < 0:
        raise ValueError("payload-bytes must be non-negative")
    if read_every < 0:
        raise ValueError("read-every must be non-negative")
    if workload not in WORKLOADS:
        raise ValueError(f"workload must be one of: {', '.join(WORKLOADS)}")
    database.parent.mkdir(parents=True, exist_ok=True)
    EventStore(database).checkpoint()
    started = time.perf_counter()
    # Run each writer in a separate process to exercise SQLite file locking and
    # WAL behavior rather than only Python-thread scheduling.
    with ProcessPoolExecutor(max_workers=writers, mp_context=benchmark_mp_context()) as executor:
        futures = [
            executor.submit(
                run_writer,
                str(database),
                writer,
                events_per_writer,
                payload_bytes,
                read_every,
                workload,
            )
            for writer in range(writers)
        ]
        results = tuple(sorted((future.result() for future in as_completed(futures)), key=lambda item: item.writer))
    elapsed = time.perf_counter() - started
    return aggregate_results(
        database,
        results,
        writers=writers,
        events_per_writer=events_per_writer,
        payload_bytes=payload_bytes,
        read_every=read_every,
        workload=workload,
        elapsed_seconds=elapsed,
    )


def run_writer(
    database: str,
    writer: int,
    events_per_writer: int,
    payload_bytes: int,
    read_every: int,
    workload: str,
) -> WorkerResult:
    """Publish benchmark events from one process.

    Called by: `run_benchmark()` through `ProcessPoolExecutor.submit()`.
    """
    db = EventStore(Path(database))
    emitter = build_emitter(db, writer, payload_bytes, workload)
    payload_data = "x" * payload_bytes
    write_latencies: list[float] = []
    read_latencies: list[float] = []
    errors: list[str] = []
    published = 0
    locked_failures = 0
    started = time.perf_counter()
    for sequence in range(events_per_writer):
        before = time.perf_counter()
        try:
            # The emitter hides whether this worker is using direct store writes
            # or the plugin-facing context event API.
            emitter(sequence, payload_data)
            published += 1
            write_latencies.append((time.perf_counter() - before) * 1000)
        except Exception as exc:  # pragma: no cover - failure shape is environment-dependent.
            message = str(exc)
            errors.append(message)
            if "database is locked" in message.casefold():
                locked_failures += 1
        if read_every and (sequence + 1) % read_every == 0:
            read_before = time.perf_counter()
            try:
                # Optional read pressure approximates follow/report views
                # querying while plugins are still producing events.
                db.recent_events(10)
                read_latencies.append((time.perf_counter() - read_before) * 1000)
            except Exception as exc:  # pragma: no cover - failure shape is environment-dependent.
                errors.append(str(exc))
    elapsed = time.perf_counter() - started
    failures = events_per_writer - published
    return WorkerResult(
        writer=writer,
        attempted=events_per_writer,
        published=published,
        failures=failures,
        locked_failures=locked_failures,
        elapsed_seconds=elapsed,
        write_latencies_ms=tuple(write_latencies),
        read_latencies_ms=tuple(read_latencies),
        errors=tuple(errors[:5]),
    )


def build_emitter(db: EventStore, writer: int, payload_bytes: int, workload: str):
    """Return the write path for one benchmark worker.

    The returned callable gives `run_writer()` one uniform publishing surface
    while still comparing direct EventStore writes to plugin-style event writes.
    """
    if workload == PLUGIN_WORKLOAD:
        context = CommandContext(
            db=db,
            source="benchmark_portscanner",
            metadata={
                "capabilities": ("db.write:port.open",),
                "command_run_id": f"benchmark-writer-{writer}",
                "pipeline_id": "sqlite-contention-benchmark",
            },
        )
        return SyntheticPortScannerEmitter(context, writer, payload_bytes).publish
    return lambda sequence, payload: db.publish(
        BENCHMARK_TOPIC,
        {
            "writer": writer,
            "sequence": sequence,
            "payload": payload,
        },
        "sqlite_contention_benchmark",
    )


@dataclass(frozen=True, slots=True)
class SyntheticPortScannerEmitter:
    """Commandlet-shaped high-volume event emitter for plugin workload tests.

    Constructed by: `build_emitter()` for `--workload plugin`. It exercises the
    same `context.events.publish()` path that native commandlets use.
    """

    context: CommandContext
    writer: int
    payload_bytes: int

    def publish(self, sequence: int, payload: str) -> None:
        """Publish one schema-valid open-port event through the plugin event API."""
        self.context.events.publish(
            "port.open",
            {
                "host": f"192.0.2.{(self.writer % 250) + 1}",
                "port": 1024 + (sequence % 40000),
                "protocol": "tcp",
                "state": "open",
                "service": "synthetic",
                "reason": "benchmark",
                "scanner": "synthetic-portscanner",
                "banner": payload if self.payload_bytes else "",
            },
        )


def benchmark_mp_context() -> Any | None:
    """Return a multiprocessing context suitable for local contention benchmarks.

    Used by: `run_benchmark()` before spawning writer processes.
    """
    try:
        return mp.get_context("fork")
    except ValueError:  # pragma: no cover - fork is unavailable on some platforms.
        return None


def aggregate_results(
    database: Path,
    results: tuple[WorkerResult, ...],
    *,
    writers: int,
    events_per_writer: int,
    payload_bytes: int,
    read_every: int,
    elapsed_seconds: float,
    workload: str = DIRECT_WORKLOAD,
) -> BenchmarkResult:
    """Aggregate per-worker benchmark results.

    Called by: `run_benchmark()` after all worker futures complete.
    """
    # Flatten latency samples across workers after preserving each worker's
    # individual result for diagnosis of skew or lock-heavy outliers.
    attempted = sum(result.attempted for result in results)
    published = sum(result.published for result in results)
    failures = sum(result.failures for result in results)
    locked_failures = sum(result.locked_failures for result in results)
    write_latencies = tuple(latency for result in results for latency in result.write_latencies_ms)
    read_latencies = tuple(latency for result in results for latency in result.read_latencies_ms)
    throughput = published / elapsed_seconds if elapsed_seconds > 0 else 0
    return BenchmarkResult(
        database=str(database),
        workload=workload,
        writers=writers,
        events_per_writer=events_per_writer,
        payload_bytes=payload_bytes,
        read_every=read_every,
        attempted=attempted,
        published=published,
        failures=failures,
        locked_failures=locked_failures,
        elapsed_seconds=elapsed_seconds,
        throughput_events_per_second=throughput,
        write_latency_ms=latency_summary(write_latencies),
        read_latency_ms=latency_summary(read_latencies),
        workers=results,
    )


def latency_summary(values: tuple[float, ...]) -> dict[str, float]:
    """Return simple latency percentiles in milliseconds.

    Used by: contention and query benchmark result aggregators.
    """
    if not values:
        return {"count": 0, "min": 0, "p50": 0, "p95": 0, "max": 0}
    ordered = tuple(sorted(values))
    return {
        "count": float(len(ordered)),
        "min": ordered[0],
        "p50": percentile(ordered, 50),
        "p95": percentile(ordered, 95),
        "max": ordered[-1],
    }


def percentile(ordered_values: tuple[float, ...], percentile_value: float) -> float:
    """Return the nearest-rank percentile from pre-sorted values.

    Used by: `latency_summary()` for p50/p95 output.
    """
    if not ordered_values:
        return 0
    rank = max(1, round((percentile_value / 100) * len(ordered_values)))
    return ordered_values[min(rank, len(ordered_values)) - 1]


def result_dict(result: BenchmarkResult) -> dict[str, Any]:
    """Return a JSON-serializable benchmark result.

    Used by: `print_result()` when `--json` is requested.
    """
    return asdict(result)


def format_result(result: BenchmarkResult) -> str:
    """Return a compact human-readable benchmark report.

    Used by: `print_result()` for the default CLI output.
    """
    lines = [
        "SQLite contention benchmark",
        f"database={result.database}",
        f"workload={result.workload}",
        f"writers={result.writers} events_per_writer={result.events_per_writer} payload_bytes={result.payload_bytes}",
        f"attempted={result.attempted} published={result.published} failures={result.failures} locked_failures={result.locked_failures}",
        f"elapsed_seconds={result.elapsed_seconds:.3f} throughput_events_per_second={result.throughput_events_per_second:.1f}",
        format_latency("write_latency_ms", result.write_latency_ms),
    ]
    if result.read_every:
        lines.append(format_latency("read_latency_ms", result.read_latency_ms))
    for worker in result.workers:
        if worker.errors:
            # Include only bounded sample errors from each worker; the full
            # failure count is already in the aggregate fields above.
            lines.append(f"worker={worker.writer} sample_errors={list(worker.errors)}")
    return "\n".join(lines)


def format_latency(label: str, summary: dict[str, float]) -> str:
    """Format one latency summary.

    Used by: `format_result()` for write and optional read latency lines.
    """
    return (
        f"{label}: count={int(summary['count'])} min={summary['min']:.3f} "
        f"p50={summary['p50']:.3f} p95={summary['p95']:.3f} max={summary['max']:.3f}"
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the benchmark CLI parser.

    Called by: `main()` and useful in tests that validate CLI argument shape.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, help="database path; defaults to a temporary file")
    parser.add_argument("--writers", type=int, default=4, help="number of concurrent writer processes")
    parser.add_argument("--events-per-writer", type=int, default=1000, help="events each writer publishes")
    parser.add_argument("--payload-bytes", type=int, default=128, help="payload bytes in each event")
    parser.add_argument("--read-every", type=int, default=0, help="each writer performs one read every N writes")
    parser.add_argument(
        "--workload",
        choices=WORKLOADS,
        default=DIRECT_WORKLOAD,
        help="write path to benchmark: direct EventStore.publish or plugin-style context.events.publish",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the benchmark CLI.

    Called by: the source-checkout wrapper script and by `python -m` execution.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.database is None:
        # Temporary DB mode is the safest default for ad hoc measurements; a
        # caller can pass --database when comparing local-vs-SSHFS storage.
        with TemporaryDirectory() as tmp:
            result = run_benchmark(
                Path(tmp, "contention.sqlite3"),
                writers=args.writers,
                events_per_writer=args.events_per_writer,
                payload_bytes=args.payload_bytes,
                read_every=args.read_every,
                workload=args.workload,
            )
            print_result(result, as_json=args.json)
            return 0
    result = run_benchmark(
        args.database,
        writers=args.writers,
        events_per_writer=args.events_per_writer,
        payload_bytes=args.payload_bytes,
        read_every=args.read_every,
        workload=args.workload,
    )
    print_result(result, as_json=args.json)
    return 0


def print_result(result: BenchmarkResult, *, as_json: bool) -> None:
    """Print benchmark output.

    Called by: `main()` after benchmark execution regardless of database mode.
    """
    if as_json:
        print(json.dumps(result_dict(result), indent=2, sort_keys=True))
    else:
        print(format_result(result))


if __name__ == "__main__":
    raise SystemExit(main())
