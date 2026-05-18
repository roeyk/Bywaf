# Bywaf Runtime Model

This document describes how Bywaf represents live and historical execution.
For short definitions, see `TERMINOLOGY.md`.

## Summary

Bywaf separates runtime execution into three nested entities:

```text
job
  pipeline
    run
```

A job is the supervised lifecycle for one submitted command line. A pipeline is
the event scope for one command expression. A run is one commandlet invocation
inside that pipeline.

For example:

```text
hostscanner 192.168.1.0/24 | portscanner | http_probe
```

creates one job, one pipeline, and three runs.

## Jobs

A job records process-oriented state:

- local job ID;
- durable job serial;
- submitted command line;
- process ID, when one exists;
- lifecycle status;
- start and finish timestamps;
- cancellation, kill, pause, and resume requests.

Foreground commands and background commands both create jobs. Background jobs
normally run in child processes. Foreground jobs may run in the interpreter
process, but they are still audited through the same lifecycle model.

Use job selectors when the question is about execution lifecycle:

```text
job show 1
job cancel 1
job kill --force 1
```

## Pipelines

A pipeline groups runs that belong to the same command expression. This is the
scope that lets downstream commandlets consume only relevant upstream events.

```text
hostscanner 127.0.0.1& | portscanner&
```

In this expression, `portscanner` should consume host events produced by that
specific `hostscanner` run, not every host event in the database. Pipeline and
parent-run scope provide that boundary.

Use pipeline selectors when the question is about the whole chain:

```text
pipeline show 1
pipeline cancel 1
artifact save pipeline=1 dir=artifacts/
```

## Runs

A run is one invocation of one commandlet inside a pipeline. Runs are the main
audit scope for plugin behavior.

A run records:

- commandlet name;
- original and normalized arguments;
- effective variable snapshot;
- command-run serial;
- pipeline membership;
- parent command-run ID;
- emitted events;
- attached artifacts and notes;
- framework requests and control signals.

Use run selectors when the question is about one commandlet stage:

```text
show run=2
artifact save run=2 dir=artifacts/
note run=2
```

## Local IDs and Serials

Bywaf has two identifier types:

- Local IDs are short numbers for interactive typing, such as `job=12`,
  `pipeline=3`, and `run=7`.
- Serials are durable audit identifiers, such as `job-...`, `pipeline-...`,
  `hostscanner-...`, `plugin-...`, and `script-...`.

Local IDs are stable and non-reused inside the current database. They are not
portable across replay, import, or a fresh database. Serials are the right
identifier for audit reports, artifacts, long-term notes, and cross-database
references.

The universal durable lookup is:

```text
show serial=<serial>
```

## Foreground and Background Execution

A command line may run in the foreground or background. Individual pipeline
stages can also be backgrounded:

```text
hostscanner 192.168.1.0/24 &
hostscanner 192.168.1.0/24& | portscanner&
```

Backgrounding changes supervision and console behavior. It does not change the
audit model: jobs, pipelines, runs, events, variables, notes, and artifacts are
still recorded.

## Runtime Control

Runtime control is auditable and message-oriented. Commands such as `pause`,
`resume`, `cancel`, `kill`, and `signal` write structured control requests.

Soft control asks the commandlet to cooperate:

```text
pause run=3
signal run=3 prune target=192.168.1.50
signal run=3 verbosity level=quiet
```

Hard control is process-oriented and may suspend or terminate execution without
giving the commandlet a chance to clean up:

```text
pause --hard job=4
kill --force job=4
```

If a commandlet is hard-paused, it cannot observe new control messages until it
resumes. The framework persists those messages so the commandlet can inspect
queued actions before taking more work.

## Variables

Commandlet variables are resolved at run creation and snapshotted into SQLite.
That snapshot is part of the audit record. Later changes to session variables do
not rewrite the recorded run context.

The practical lookup model is:

```text
run snapshot -> commandlet variables -> global variables -> defaults
```

This lets multiple instances of the same commandlet run concurrently with
different behavior:

```text
hostscanner 192.168.1.0/24 -s &
hostscanner 10.0.0.0/24 &
```

## Runtime Listings

Runtime listing commands show table-oriented views:

```text
jobs
runs
pipelines
info
```

By default, listings focus on active entities. `--all` includes historical
entities and shows lifecycle state such as in progress, failed, completed, or
stale. Listings also include artifact counts when available.

## Plugin Author Implications

Plugin code should treat the `CommandContext` as the source of run state. Do
not store invocation-specific mutable state on the commandlet object unless the
framework guarantees a fresh object for that invocation.

Prefer:

```python
def run(self, context, args, input_events):
    silent = "--silent" in args
```

Avoid:

```python
class Scanner:
    def __init__(self):
        self.silent = False
```

Runtime control-aware plugins should periodically read `context.signals` and
emit outcome events when they apply or ignore control messages.

The commandlet's integration type affects failure behavior. A framework-native
plugin usually fails with a Python exception, a library-backed plugin can fail
inside the interpreter process, an external-process wrapper reports child
process exit state, and a native/FFI plugin may require stronger isolation.
See `CAPABILITY_MODEL.md` for the full plugin integration taxonomy.
