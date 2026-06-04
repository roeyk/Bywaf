# Performance Benchmarks

This page records repeatable local benchmarks for storage and runtime behavior.
They are maintainer tools, not ordinary CI pass/fail tests.

## SQLite Contention

Use the SQLite contention benchmark to measure current direct-write event-store
behavior before considering a single-writer queue or backend change:

```bash
PYTHONPATH=. python3 scripts/sqlite_contention_benchmark.py \
  --writers 4 \
  --events-per-writer 1000 \
  --payload-bytes 128 \
  --read-every 100
```

For machine-readable output:

```bash
PYTHONPATH=. python3 scripts/sqlite_contention_benchmark.py \
  --writers 4 \
  --events-per-writer 1000 \
  --payload-bytes 128 \
  --read-every 100 \
  --json
```

The default workload writes through `EventStore.publish()` from multiple
processes, which exercises the same SQLite/WAL path used by Bywaf workers:

```bash
PYTHONPATH=. python3 scripts/sqlite_contention_benchmark.py \
  --workload direct \
  --writers 4 \
  --events-per-writer 1000 \
  --payload-bytes 128 \
  --read-every 100
```

For plugin-shaped event pressure, use `--workload plugin`. This creates a
commandlet-style `CommandContext` in each writer process and publishes
schema-valid `port.open` events through `context.events.publish(...)`, including
normal provenance and capability-audit behavior:

```bash
PYTHONPATH=. python3 scripts/sqlite_contention_benchmark.py \
  --workload plugin \
  --writers 4 \
  --events-per-writer 1000 \
  --payload-bytes 128 \
  --read-every 100
```

The benchmark reports:

- attempted and published event counts;
- total failures and `database is locked` failures;
- write latency percentiles;
- optional read latency percentiles;
- aggregate throughput.

Small smoke tests cover the benchmark code in CI. Real contention decisions
should come from explicit local runs with enough events and writers to match
the expected assessment workload.

## SQLite Query Scale

Use the SQLite query benchmark to measure read-heavy behavior after a project
database has accumulated assessment-sized event volume:

```bash
PYTHONPATH=. python3 scripts/sqlite_query_benchmark.py \
  --events 100000 \
  --repetitions 5 \
  --payload-bytes 128
```

For machine-readable output:

```bash
PYTHONPATH=. python3 scripts/sqlite_query_benchmark.py \
  --events 100000 \
  --repetitions 5 \
  --payload-bytes 128 \
  --json
```

The query benchmark populates synthetic report-like events when the target
database has fewer than `--events` rows, then measures:

- store open/schema-check cost;
- latest event ID lookup;
- topic listing;
- recent event slices;
- single-topic event queries;
- subscription fetch queries;
- scoped pipeline and step queries;
- report-context topic group queries;
- JSONL audit-export-style scans.

To include maintenance timing, add `--maintenance`:

```bash
PYTHONPATH=. python3 scripts/sqlite_query_benchmark.py \
  --events 100000 \
  --repetitions 5 \
  --payload-bytes 128 \
  --maintenance
```

Maintenance timing covers table counts, WAL checkpoint/truncation, plaintext
SQLite export copy, and `VACUUM`. These operations mutate the target database
file, so use `--maintenance` intentionally when benchmarking an existing
project database.

Use `--database path/to/bywaf.sqlite3` to run the query suite against an
existing project or benchmark database. Keep JSON captures from large local
runs with hardware/context notes so future storage changes can be compared
against the same workload shape.
