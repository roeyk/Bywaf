# Bywaf Terminology

Bywaf uses a small set of runtime terms consistently. These definitions are
intended to keep the CLI, documentation, plugin API, and audit records aligned.

## Document Index

- [Job](#job)
- [Pipeline](#pipeline)
- [Step](#step)
- [Local ID](#local-id)
- [Serial](#serial)
- [Event](#event)
- [Topic](#topic)
- [Commandlet](#commandlet)
- [Inventory Command](#inventory-command)
- [Plugin](#plugin)
- [Capability](#capability)

## Job

A job is the supervised execution lifecycle for foreground or background work.

A job records process-oriented state:

- local job ID;
- durable job serial;
- command line;
- process ID, when applicable;
- lifecycle status;
- start and finish timestamps;
- cancellation/end state.

Foreground command lines and background command lines both create jobs. A
background job usually maps to a worker process. A foreground job may run
in-process but is still audited through the same lifecycle events. Jobs do not
define the audit scope by themselves; they supervise work that may execute one
or more pipeline steps.

Use job selectors when you want to control or inspect execution lifecycle:

```text
job 1
job job-...
job cancel 1
job end --hard 1
```

## Pipeline

A pipeline is a group of one or more commandlet steps that belong to the same
command expression or attached workflow.

The common case is a pipe expression:

```text
hostscanner 192.168.1.0/24 | portscanner | http_probe
```

That creates one pipeline containing three commandlet steps. The pipeline is the
scope that lets downstream commandlets consume only the upstream events that
belong to the same workflow. Operationally, jobs are chained together into a
pipeline by the steps they supervise; one job may contribute the whole chain,
or multiple jobs may contribute steps when commandlets are attached later.

Use pipeline selectors when you want to inspect or control the whole chain:

```text
pipeline 1
pipeline cancel 1
artifact export pipeline=1 dir=artifacts/
```

## Step

A step is one invocation of one commandlet inside a pipeline.

The user-facing list and detail commands are `step` and `step <id>`, and
selectors use `step=...`. Some persisted database columns still use historical
names such as `command_run_id`; treat those as storage details for the same
pipeline-step record.

For this command:

```text
hostscanner 192.168.1.0/24 | portscanner | http_probe
```

Bywaf creates roughly:

```text
job=1
  pipeline=1
    step=1  hostscanner
    step=2  portscanner
    step=3  http_probe
```

A step is the audit scope for a specific commandlet invocation. It records the
commandlet, arguments, effective variable snapshot, emitted events, artifacts,
upstream parent step, and pipeline membership.

Signals target concrete execution receivers. A step can receive plugin-domain
signals because it is the commandlet execution context; plugin code reads those
with `context.signals.pending(...)`. A job can receive framework lifecycle
signals because it supervises a process or foreground execution. A pipeline does
not receive plugin-domain signals directly because it is only a grouping scope;
pipeline-level control commands fan out to associated job or step.

Use `step=` selectors when you care about one pipeline step of a workflow:

```text
event step=2
artifact export step=2 dir=artifacts/
note step=2
```

## Local ID

A local ID is the short number used for interactive work in one database.

Examples:

```text
job=12
step=7
pipeline=3
```

Local IDs are stable inside the current database and should not be reused
there. They are not audit-grade portable identifiers across replay, import, or
a fresh database.

## Serial

A serial is the durable audit/provenance identifier.

Examples:

```text
job-...
hostscanner-...
pipeline-...
artifact-...
script-...
plugin-...
```

Serials are the right identifiers for audit reports, replayable notes,
cross-database references, and long-term provenance. The universal selector is:

```text
event serial=<serial>
```

Serial bodies use Crockford Base32. Bywaf stores the full prefixed serial, but
runtime tables display a short body prefix. That short value can be typed back
into selectors as long as it is unique in the active database.

## Event

An event is a structured database record emitted by a commandlet or framework
component.

Events are the canonical long-term record of what happened. Console output,
reports, tables, dashboards, and future GUIs should derive from events rather
than from terminal scrollback.

## Topic

A topic is the event type name.

Examples:

```text
host.found
port.open
artifact.imported
artifact.attached
job.started
policy.evaluated
```

Commandlets publish and consume topics to cooperate through the central event
database.

## Commandlet

A commandlet is a user-facing command provided by a plugin or by the framework.

Examples:

```text
hostscanner
portscanner
http_probe
artifact
job
pipeline
```

A plugin may provide one commandlet or multiple commandlets.

## Inventory Command

An inventory command is an operator-facing commandlet that summarizes the
project's accumulated target knowledge from normalized events. Inventory
commands answer questions such as "which hosts are known?", "which services are
open?", and "which web endpoints exist?" without requiring the operator to know
which scanner produced the underlying events.

Current examples include:

```text
hosts
services
web
ports
```

Inventory commands are distinct from runtime/store views such as `job`,
`pipeline`, `step`, `event`, and `artifact`, which inspect execution and storage
bookkeeping.

## Plugin

A plugin is a provider of commandlets and related defaults, completion behavior,
planning behavior, and capability declarations.

Plugins should use the framework APIs for output, artifacts, process execution,
events, variables, and live-control signals so their behavior remains auditable.

## Capability

A capability is a declared or audited permission-like behavior.

Examples:

```text
db.raw
db.write:host.found
artifact.write
framework.console.output
framework.process.run
```

Capabilities help operators understand what a commandlet intended to do and
what it actually did.
