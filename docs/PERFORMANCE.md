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

## Current SQLite Scale Guidance

The current local benchmark baseline supports keeping SQLite as Bywaf's
local-first default for single-operator projects. On the current development
machine, synthetic report-like databases up to 1,000,000 events showed bounded
interactive reads and report topic-group queries below 100 ms p95:

| Workload | Measured scale | p95 result |
|---|---:|---:|
| Direct concurrent writes | 24 writers, 480,000 events | 8.370 ms write latency |
| Plugin-shaped concurrent writes | 24 writers, 480,000 `port.open` events | 8.586 ms write latency |
| Recent event listing | 1,000,000 events, `recent_1000` | 3.231 ms |
| Topic query | 1,000,000 events, `topic_port_open_10000` | 41.523 ms |
| Scoped pipeline query | 1,000,000 events, `scoped_pipeline_port_open_1000` | 61.295 ms |
| Report context query group | 1,000,000 events, `report_context_topics_1000` | 39.211 ms |
| Capped JSONL-style audit scan | 1,000,000-event DB, 100,000 serialized events | 632.443 ms |
| Plain SQLite export copy | 500,000-event DB, 207,712,256 bytes copied | 53.262 ms |
| Vacuum | 500,000-event DB | 313.716 ms |

These numbers are not product limits. They are the current regression baseline
for local maintainer decisions. If a project reaches multi-million event
volume, sustained background pipelines, or repeated report/export operations
that feel slow to an operator, capture a fresh benchmark on that database
before changing storage architecture.

For ordinary local projects:

- keep emitting normalized, operator-meaningful events rather than noisy
  internal retry/packet/debug events;
- use `db checkpoint` before copying database files outside Bywaf;
- use `db vacuum` after large deletions or retention/compaction work, not as a
  routine per-scan step;
- split unrelated client assessments into separate project databases when the
  event log is no longer useful as one audit history;
- consider optional backend work only after a measured workload shows lock
  failures, sustained query latency, or maintenance/export costs that are
  operator-visible.

## SQLite Settings Review

The main event database and artifact database both use short-lived SQLite
connections with WAL enabled and a 30-second busy timeout:

- connection timeout: `30` seconds;
- `PRAGMA journal_mode=WAL`;
- `PRAGMA busy_timeout=30000`;
- autocommit connections, with each event publish inserted as one durable
  statement;
- explicit checkpoint support through `db checkpoint`;
- explicit `VACUUM` support through `db vacuum`.

Current decision: leave these settings unchanged.

Measured 24-writer direct and plugin-shaped contention runs produced zero
write failures and zero `database is locked` failures. Query benchmarks through
1,000,000 synthetic events kept bounded reads comfortably below 100 ms p95, and
500,000-event maintenance operations were sub-second on the current machine.
That does not justify a single-writer queue, transaction batching layer,
different busy timeout, or automatic checkpoint/vacuum schedule yet.

Known watch points:

- `topics` uses `SELECT DISTINCT topic FROM events ORDER BY topic`; it is
  total-table-size dependent, reaching 25.816 ms p95 at 1,000,000 synthetic
  events. Keep it as-is unless real projects make topic listing visibly slow.
- Audit JSON/JSONL scans are linear in exported row count. This is expected;
  use selectors or SQLite export for large preservation-oriented exports.
- Transaction batching would improve synthetic bulk insertion but would also
  change event durability boundaries. Keep one-event durable writes unless a
  measured plugin workload proves batching is needed.
- Retention/compaction remains a policy problem, not just a SQLite operation.
  Add it as separate work once Bywaf has clear operator rules for what history
  may be removed or archived.
