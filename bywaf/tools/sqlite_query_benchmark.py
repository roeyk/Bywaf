"""SQLite event-store query benchmark.

Provides repeatable measurements for read-heavy event-store behavior after
large assessment-sized event volumes have accumulated.

Used by:
- scripts/sqlite_query_benchmark.py: source-checkout command wrapper.
- maintainers: collect PERF-001 measurements for report/inventory/audit paths.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable

from ..db import EventStore
from ..event import Event
from ..subscriptions import Subscription
from .sqlite_contention_benchmark import latency_summary


REPORT_CONTEXT_TOPICS = (
    "host.found",
    "name.resolved",
    "port.open",
    "service.detected",
    "http.endpoint",
    "http.path",
    "tls.certificate",
    "web.waf.detected",
    "web.screenshotted_host",
    "network.route.hop",
)


@dataclass(frozen=True, slots=True)
class QueryMeasurement:
    """Repeated latency measurements for one query path."""

    name: str
    rows: int
    latency_ms: dict[str, float]


@dataclass(frozen=True, slots=True)
class QueryBenchmarkResult:
    """Aggregated query benchmark report."""

    database: str
    events: int
    repetitions: int
    populate_seconds: float
    database_bytes: int
    measurements: tuple[QueryMeasurement, ...]
    maintenance_measurements: tuple[QueryMeasurement, ...]


def run_query_benchmark(
    database: Path,
    *,
    events: int,
    repetitions: int,
    payload_bytes: int = 128,
    maintenance: bool = False,
) -> QueryBenchmarkResult:
    """Populate a benchmark DB if needed and measure common read paths."""
    if events < 1:
        raise ValueError("events must be at least 1")
    if repetitions < 1:
        raise ValueError("repetitions must be at least 1")
    if payload_bytes < 0:
        raise ValueError("payload-bytes must be non-negative")
    database.parent.mkdir(parents=True, exist_ok=True)
    populate_seconds = populate_database(database, events=events, payload_bytes=payload_bytes)
    store = EventStore(database)
    measurements = tuple(measure_query_paths(store, repetitions=repetitions, export_limit=min(events, 100_000)))
    maintenance_measurements = tuple(measure_maintenance_paths(store, repetitions=repetitions)) if maintenance else ()
    return QueryBenchmarkResult(
        database=str(database),
        events=store.latest_event_id(),
        repetitions=repetitions,
        populate_seconds=populate_seconds,
        database_bytes=database_size(database),
        measurements=measurements,
        maintenance_measurements=maintenance_measurements,
    )


def populate_database(database: Path, *, events: int, payload_bytes: int) -> float:
    """Populate a synthetic report-like event database unless it is large enough."""
    store = EventStore(database)
    existing = store.latest_event_id()
    if existing >= events:
        return 0.0
    started = time.perf_counter()
    payload_padding = "x" * payload_bytes
    with sqlite3.connect(database) as conn:
        rows = (
            synthetic_event_row(sequence, payload_padding)
            for sequence in range(existing, events)
        )
        conn.executemany(
            """
            INSERT INTO events(
                topic,
                payload_json,
                source,
                created_at,
                pipeline_id,
                command_run_id,
                parent_command_run_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
    EventStore(database).checkpoint()
    return time.perf_counter() - started


def synthetic_event_row(sequence: int, payload_padding: str) -> tuple[str, str, str, str, str, str, str | None]:
    """Return one synthetic event row shaped like normal scanner/report data."""
    topic = REPORT_CONTEXT_TOPICS[sequence % len(REPORT_CONTEXT_TOPICS)]
    pipeline_id = f"pipeline-{sequence // 10_000:04d}"
    command_run_id = f"step-{(sequence // 1_000) % 1_000:04d}"
    payload: dict[str, Any] = {
        "host": f"192.0.{(sequence // 250) % 256}.{(sequence % 250) + 1}",
        "sequence": sequence,
        "payload": payload_padding,
    }
    if topic in {"port.open", "service.detected"}:
        payload.update({"port": 1024 + (sequence % 40_000), "protocol": "tcp", "service": "synthetic"})
    elif topic == "http.endpoint":
        payload["url"] = f"https://example-{sequence % 1000}.test/"
    elif topic == "http.path":
        payload.update({"url": f"https://example-{sequence % 1000}.test/admin", "path": "/admin", "status": 200})
    elif topic == "tls.certificate":
        payload["subject"] = f"CN=example-{sequence % 1000}.test"
    elif topic == "web.waf.detected":
        payload["waf"] = "synthetic"
    elif topic == "network.route.hop":
        payload["hop"] = sequence % 30
    return (
        topic,
        json.dumps(payload, sort_keys=True),
        "sqlite_query_benchmark",
        "2026-01-01T00:00:00+00:00",
        pipeline_id,
        command_run_id,
        None,
    )


def measure_query_paths(store: EventStore, *, repetitions: int, export_limit: int) -> list[QueryMeasurement]:
    """Measure representative event read paths."""
    latest = store.latest_event_id()
    pipeline_id = f"pipeline-{max(0, latest - 1) // 10_000:04d}"
    command_run_id = f"step-{((max(0, latest - 1) // 1_000) % 1_000):04d}"
    operations: tuple[tuple[str, Callable[[], int]], ...] = (
        ("open_store", lambda: open_store(store)),
        ("latest_event_id", lambda: scalar_count(store.latest_event_id())),
        ("topics", lambda: len(store.topics())),
        ("recent_25", lambda: len(store.recent_events(25))),
        ("recent_1000", lambda: len(store.recent_events(1000))),
        ("topic_port_open_1000", lambda: len(store.events_for_topic("port.open", limit=1000))),
        ("topic_port_open_10000", lambda: len(store.events_for_topic("port.open", limit=10000))),
        (
            "fetch_port_open_1000",
            lambda: len(store.fetch(Subscription(topics=("port.open",), limit=1000))),
        ),
        (
            "scoped_pipeline_port_open_1000",
            lambda: len(store.fetch(Subscription(topics=("port.open",), pipeline_id=pipeline_id, limit=1000))),
        ),
        (
            "scoped_step_port_open_1000",
            lambda: len(store.fetch(Subscription(topics=("port.open",), command_run_id=command_run_id, limit=1000))),
        ),
        ("report_context_topics_1000", lambda: report_context_topics(store, limit=1000)),
        ("audit_jsonl_scan_100000", lambda: audit_jsonl_scan(store, limit=export_limit)),
    )
    return [measure_operation(name, operation, repetitions=repetitions) for name, operation in operations]


def measure_maintenance_paths(store: EventStore, *, repetitions: int) -> list[QueryMeasurement]:
    """Measure explicit maintenance operations that may mutate the DB file."""
    operations: tuple[tuple[str, Callable[[], int]], ...] = (
        ("table_counts", lambda: len(store.table_counts())),
        ("checkpoint", lambda: maintenance_checkpoint(store)),
        ("sqlite_export_copy", lambda: sqlite_export_copy(store)),
        ("vacuum", lambda: maintenance_vacuum(store)),
    )
    return [measure_operation(name, operation, repetitions=repetitions) for name, operation in operations]


def maintenance_checkpoint(store: EventStore) -> int:
    """Measure WAL checkpoint/truncation."""
    store.checkpoint()
    return 1


def maintenance_vacuum(store: EventStore) -> int:
    """Measure VACUUM rebuild cost."""
    store.vacuum()
    return 1


def sqlite_export_copy(store: EventStore) -> int:
    """Measure plaintext SQLite audit export copy cost."""
    store.checkpoint()
    with TemporaryDirectory() as tmp:
        output = Path(tmp, "audit.sqlite3")
        shutil.copy2(store.path, output)
        return output.stat().st_size


def open_store(store: EventStore) -> int:
    """Measure EventStore construction and schema check cost."""
    EventStore(Path(store.path))
    return 1


def scalar_count(value: int) -> int:
    """Return one scalar result as a row count for reporting consistency."""
    del value
    return 1


def report_context_topics(store: EventStore, *, limit: int) -> int:
    """Measure the topic-group query shape used by report context selection."""
    count = 0
    for topic in REPORT_CONTEXT_TOPICS:
        count += len(store.events_matching(topic=topic, limit=limit))
    return count


def audit_jsonl_scan(store: EventStore, *, limit: int) -> int:
    """Measure all-event scan and JSON serialization used by JSONL audit export."""
    with store.connect() as conn:
        rows = conn.execute("SELECT * FROM events ORDER BY id ASC LIMIT ?", (limit,))
        count = 0
        for row in rows:
            event = Event.from_row(row)
            json.dumps(
                {
                    "id": event.id,
                    "topic": event.topic,
                    "source": event.source,
                    "created_at": event.created_at.isoformat(),
                    "pipeline_id": event.pipeline_id,
                    "command_run_id": event.command_run_id,
                    "parent_command_run_id": event.parent_command_run_id,
                    "payload": event.payload,
                },
                sort_keys=True,
            )
            count += 1
    return count


def measure_operation(name: str, operation: Callable[[], int], *, repetitions: int) -> QueryMeasurement:
    """Run one query operation repeatedly and summarize latency."""
    latencies: list[float] = []
    rows = 0
    for _ in range(repetitions):
        started = time.perf_counter()
        rows = operation()
        latencies.append((time.perf_counter() - started) * 1000)
    return QueryMeasurement(name=name, rows=rows, latency_ms=latency_summary(tuple(latencies)))


def database_size(database: Path) -> int:
    """Return database and SQLite sidecar bytes."""
    total = 0
    for path in (database, database.with_name(database.name + "-wal"), database.with_name(database.name + "-shm")):
        if path.exists():
            total += path.stat().st_size
    return total


def result_dict(result: QueryBenchmarkResult) -> dict[str, Any]:
    """Return a JSON-serializable benchmark result."""
    return asdict(result)


def format_result(result: QueryBenchmarkResult) -> str:
    """Return a compact human-readable benchmark report."""
    lines = [
        "SQLite query benchmark",
        f"database={result.database}",
        f"events={result.events} repetitions={result.repetitions} database_bytes={result.database_bytes}",
        f"populate_seconds={result.populate_seconds:.3f}",
    ]
    for measurement in result.measurements:
        lines.append(format_measurement(measurement))
    if result.maintenance_measurements:
        lines.append("maintenance:")
        for measurement in result.maintenance_measurements:
            lines.append(format_measurement(measurement))
    return "\n".join(lines)


def format_measurement(measurement: QueryMeasurement) -> str:
    """Format one benchmark measurement."""
    latency = measurement.latency_ms
    return (
        f"{measurement.name}: rows={measurement.rows} "
        f"p50={latency['p50']:.3f}ms p95={latency['p95']:.3f}ms max={latency['max']:.3f}ms"
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the benchmark CLI parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, help="database path; defaults to a temporary file")
    parser.add_argument("--events", type=int, default=100_000, help="minimum synthetic events to populate")
    parser.add_argument("--repetitions", type=int, default=5, help="query repetitions per measured path")
    parser.add_argument("--payload-bytes", type=int, default=128, help="payload bytes in each synthetic event")
    parser.add_argument(
        "--maintenance",
        action="store_true",
        help="also time checkpoint, plaintext SQLite export copy, and VACUUM operations",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the query benchmark CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.database is None:
        with TemporaryDirectory() as tmp:
            result = run_query_benchmark(
                Path(tmp, "query.sqlite3"),
                events=args.events,
                repetitions=args.repetitions,
                payload_bytes=args.payload_bytes,
                maintenance=args.maintenance,
            )
            print_result(result, as_json=args.json)
            return 0
    result = run_query_benchmark(
        args.database,
        events=args.events,
        repetitions=args.repetitions,
        payload_bytes=args.payload_bytes,
        maintenance=args.maintenance,
    )
    print_result(result, as_json=args.json)
    return 0


def print_result(result: QueryBenchmarkResult, *, as_json: bool) -> None:
    """Print benchmark output."""
    if as_json:
        print(json.dumps(result_dict(result), indent=2, sort_keys=True))
    else:
        print(format_result(result))


if __name__ == "__main__":
    raise SystemExit(main())
