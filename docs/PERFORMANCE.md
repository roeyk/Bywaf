# Performance

This page explains how Bywaf performance is measured, how operators and plugin
authors can avoid common slow paths, and which architectural optimizations are
under consideration. It also records repeatable local benchmarks for storage
and runtime behavior. Benchmarks are maintainer tools, not ordinary CI
pass/fail tests.

**Audience**

This document is for Bywaf operators diagnosing slow startup, REPL, reporting,
or scan behavior; plugin authors who need to publish useful results without
flooding the event store; and framework maintainers deciding whether a
performance issue should be solved by usage guidance, code-level optimization,
or a deeper architecture change.

**Related Documents**

- [Documentation Roadmap](README.md): role-oriented entry points into the Bywaf
  documentation set.
- [Documentation Paths](DOCUMENTATION_PATHS.md): role-based reading sequences
  for operators, plugin developers, framework developers, and maintainers.
- [Architecture Metrics](ARCHITECTURE_METRICS.md): static dependency, size,
  complexity, and documentation metrics used during refactoring decisions.
- [Testing](TESTING.md): validation commands for framework, plugin, packaging,
  and metrics changes.
- [Framework Development](FRAMEWORK_DEVELOPMENT.md): maintainer workflow,
  package map, and common change paths.
- [Retention And Compaction](RETENTION_AND_COMPACTION.md): evidence lifecycle
  policy for project splitting, archiving, and future compaction.
- [Plugin Author Event Schemas](plugin_author/event-schemas.md): normalized
  event topics and high-volume publishing expectations for plugins.
- [Wrapper Robustness](plugin_author/wrapper-robustness.md): evidence,
  fixture, parser, and support expectations for process-wrapper plugins.

## Contents

- [Measurement First](#measurement-first)
- [Runtime Usage And Configuration](#runtime-usage-and-configuration)
- [Plugin Author Performance Guidelines](#plugin-author-performance-guidelines)
- [Optimization Approach](#optimization-approach)
- [Architectural Options](#architectural-options)
- [SQLite Contention](#sqlite-contention)
- [SQLite Query Scale](#sqlite-query-scale)
- [Current SQLite Scale Guidance](#current-sqlite-scale-guidance)
- [SQLite Settings Review](#sqlite-settings-review)

## Measurement First

Performance changes should start from a measured symptom, not from architectural
confidence. For user-visible latency, capture the operation that feels slow and
measure the relevant path:

- use `cProfile` or targeted timings for startup, REPL idle loops, command
  dispatch, plugin discovery, and report generation;
- use the SQLite contention and query benchmarks below for event-store scale
  questions;
- keep local-filesystem measurements separate from SSHFS or other network
  filesystem measurements;
- record enough context to compare future runs: machine, storage location,
  database size, event count, plugin workload, and command line.

If a performance complaint involves an unusual runtime shape, such as running
source code over SSHFS, measure that shape separately from the normal local
baseline. A network filesystem result can explain a real user problem without
justifying a broad storage or architecture change.

## Runtime Usage And Configuration

For ordinary local projects:

- keep Bywaf's local runtime state on a local filesystem on the machine
  executing Bywaf;
- use named projects to separate unrelated client assessments;
- use selectors for large report, audit, and result views instead of exporting
  or rendering broad history by default;
- use `db checkpoint` before copying SQLite database files outside Bywaf;
- use `db vacuum` after large deletions or explicit retention/compaction work,
  not as a routine per-scan step;
- split unrelated assessments into separate project databases when one event
  log no longer reads as a useful audit history.

Bywaf's local runtime state includes the SQLite database, WAL/SHM sidecars,
artifact databases and retained artifacts, command history, project config,
scripts, plugin override directories, and other frequently rewritten or
appended files. That state normally belongs on the same machine that is running
Bywaf and carrying out the authorized assessment.

Network filesystems can make interactive startup and REPL prompts feel slow
even when local benchmarks are healthy. Python startup and plugin discovery do
many small metadata and source/bytecode reads, and SQLite uses frequent small
opens, reads, writes, and lock checks. Over SSHFS these operations can become
network round trips and can also weaken SQLite's normal local-filesystem
locking assumptions.

Prefer either an SSH session that runs Bywaf on the remote host, or a local
checkout with local runtime state. If you intentionally run Bywaf from a source
tree mounted over SSHFS, keep the active database on a local filesystem on the
machine executing Python:

```bash
bywaf --database /var/tmp/bywaf-local/bywaf.sqlite3 repl
```

or use a named project, which stores project state under the local user's
`~/.bywaf/projects/<name>/` directory:

```bash
bywaf project=client-a
```

This does not remove the source-import cost of running code from SSHFS, but it
keeps SQLite event, job, audit, trigger, and artifact metadata traffic local.

## Plugin Author Performance Guidelines

Plugins should publish normalized, operator-meaningful data rather than noisy
low-level traces. High-volume scans should preserve raw tool output as
artifacts and emit compact facts or findings that downstream review, report,
and bundle commands can interpret.

Good plugin behavior:

- emit stable facts such as `port.open`, `http.endpoint`, or
  `finding.candidate` instead of per-retry or per-packet debug records;
- attach raw scanner output as artifacts when operators may need the original
  transcript;
- batch interpretation in plugin code before publishing many redundant events;
- declare database actions, capabilities, emitted topics, and safety behavior
  so the framework can audit the run without extra inference work;
- use background jobs for long-running scans rather than blocking the REPL;
- keep report-facing payloads bounded and structured so dedupe/report commands
  do not need to parse unbounded free text.

Avoid treating the event store as a debug log for every internal loop. Debug
or parser detail can live in artifacts, diagnostic topics, or explicit verbose
modes when those become standardized.

## Optimization Approach

Optimization should progress from least invasive to most invasive:

1. Measure the slow path with a profiler, benchmark, or focused timing.
2. Try usage and configuration fixes first, such as local runtime state,
   selectors, project splitting, checkpointing, or avoiding SSHFS for SQLite.
3. Apply code-level optimization when the profiler identifies avoidable work,
   such as redundant DB writes, repeated cursor reads, high-frequency idle
   polling, unnecessary plugin metadata recomputation, or unbounded list scans.
4. Consider architectural changes only when measurements show that local fixes
   are not enough.
5. Preserve correctness: audit durability, event ordering, artifact retention,
   SQLite locking behavior, authorization records, and safety boundaries matter
   more than shaving small amounts of latency.

The 2026-06-06 REPL latency fix followed this pattern: profiling showed that
idle service-trigger polling rewrote durable trigger state on every empty
Enter. The narrow fix skipped the write when the trigger cursor had not moved,
improving a 200-iteration empty REPL loop from 1.319 seconds to 0.167 seconds
without changing storage architecture.

## Architectural Options

The following options are available for future work, but none should be adopted
without measurements from a real workload:

- lazy or staged plugin loading if startup/import time becomes operator-visible
  as the bundled or external plugin catalog grows;
- a broader `--state-dir` option if operators need to move database, history,
  artifacts, config, scripts, and plugin overrides together;
- throttled or event-aware REPL idle polling if background request checks become
  a recurring prompt-latency source;
- scoped long-lived REPL database connections if short-lived SQLite connection
  setup becomes a proven interactive bottleneck;
- transaction batching for high-volume event publishers, balanced against
  event durability boundaries;
- a single-writer queue if real plugin workloads show lock failures or
  unacceptable write latency;
- optional PostgreSQL or another backend only after local SQLite measurements
  show sustained operator-visible limits.

These are design levers, not defaults. Bywaf should continue to prefer the
simple local-first path while benchmark and operator evidence supports it.

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

For current operator guidance, see
[Runtime Usage And Configuration](#runtime-usage-and-configuration). For
plugin event-volume guidance, see
[Plugin Author Performance Guidelines](#plugin-author-performance-guidelines).

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
  The current policy is documented in
  [Retention And Compaction](RETENTION_AND_COMPACTION.md): preserve by
  default, split unrelated projects, and require explicit export/archive before
  any future destructive compaction.
