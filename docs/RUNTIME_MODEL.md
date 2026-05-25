# Bywaf Runtime Model

This document describes how Bywaf represents live and historical execution.
For short definitions, see `TERMINOLOGY.md`.

## Document Index

- [Summary](#summary)
- [Jobs](#jobs)
- [Pipelines](#pipelines)
- [Runs](#runs)
- [Local IDs and Serials](#local-ids-and-serials)
- [Foreground and Background Execution](#foreground-and-background-execution)
- [Runtime Control](#runtime-control)
- [Variables](#variables)
- [Runtime Listings](#runtime-listings)
- [Plugin Author Implications](#plugin-author-implications)

## Summary

Bywaf separates runtime execution into three related entities:

```text
pipeline
  run

job
  supervises one or more runs
```

A pipeline is the event scope for one command expression or attached workflow.
A run is one commandlet invocation inside that pipeline. A job is the
supervised lifecycle for foreground or background work that executes one or
more runs.

For example:

```text
hostscanner 192.168.1.0/24 | portscanner | http_probe
```

creates one job, one pipeline, and three runs. If another commandlet is
attached to that pipeline later, the same pipeline can be associated with an
additional job and additional runs.

## Jobs

A job records process-oriented state:

- local job ID;
- durable job serial;
- submitted command line;
- process ID, when one exists;
- lifecycle status;
- start and finish timestamps;
- cancellation, end/kill, pause, and resume requests.

Foreground commands and background commands both create jobs. Background jobs
normally run in child processes. Foreground jobs may run in the interpreter
process, but they are still audited through the same lifecycle model. A job
does not own the pipeline identity; it supervises execution work that is linked
to pipeline and run IDs through the run variable snapshot and emitted events.

Use job selectors when the question is about execution lifecycle:

```text
job show 1
job cancel 1
job end --hard 1
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

Jobs are chained together into pipelines by the runs they supervise. For
example, `pipeline attach` starts a new background job whose run joins an
existing pipeline.

Use pipeline selectors when the question is about the whole chain:

```text
pipeline show 1
pipeline cancel 1
artifact export pipeline=1 dir=artifacts/
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
event run=2
artifact export run=2 dir=artifacts/
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
event serial=<serial>
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
`resume`, `cancel`, `end`, `kill`, and `signal` write structured control
requests.

Soft control asks the commandlet to cooperate:

```text
pause run=3
signal run=3 prune target=192.168.1.50
signal run=3 verbosity level=quiet
```

`signal run=...` is the normal route for plugin-domain messages because a run
is the commandlet execution context. `signal job=...` is for supervisor-level
framework lifecycle control. A pipeline is not an execution receiver, so
plugin-domain signals are not sent to `pipeline=` directly; pipeline-aware
commands fan out through the jobs or runs associated with the pipeline.

`pause` defaults to soft/cooperative behavior. Add `--hard` when the framework
should suspend the associated process. `end` and `kill` are synonyms: both
default to cooperative `--soft`, and `--hard` force-terminates the affected
process.

Hard control is process-oriented and may suspend or terminate execution without
giving the commandlet a chance to clean up:

```text
pause --hard job=4
end --hard job=4
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

## Preferences

Preferences are user-owned defaults, not runtime evidence. The intended `pref`
model stores them outside project databases under `~/.bywaf`, for example in
`~/.bywaf/preferences.toml`.

Use preferences for operator experience and cross-project defaults:

- display colors and table style;
- prompt behavior;
- preferred pager/editor/tool paths;
- plugin UX defaults, such as `plugins.portscanner.default-arguments`.

Use variables for execution state that can affect command behavior:

- `global.policy.network.allow`;
- `discovery/hostscanner.targets`;
- `http/http_probe.cookie-file`;
- commandlet arguments captured for a run.

The boundary is audit-driven: preferences may influence defaults, but any
effective value that changes evidence-producing execution should be captured in
the run snapshot or emitted event payload. Plugins may read preferences for
defaults. Plugin writes to preferences should be framework-mediated and
user-approved, not silent writes to `~/.bywaf/preferences.toml`.

## Runtime Listings

Runtime listing commands show table-oriented views:

```text
jobs
steps
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
