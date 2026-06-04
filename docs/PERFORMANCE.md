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
