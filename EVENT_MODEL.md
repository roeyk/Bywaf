# Bywaf Event Model

Bywaf uses SQLite as an append-oriented event store. Commandlets cooperate by
publishing and consuming structured events instead of passing ad hoc files or
terminal output between tools.

## Event Rows

An event row records:

- numeric event ID;
- topic;
- JSON payload;
- source commandlet or framework component;
- timestamp;
- pipeline ID;
- command-run ID;
- parent command-run ID.

The row scope is authoritative. Payloads may repeat fields such as
`pipeline_id` or `command_run_id` for convenience, but the database columns are
the canonical runtime scope.

## Topics

A topic names what happened.

Examples:

```text
host.found
port.open
http.endpoint
artifact.attached
framework.console.alert.requested
console.alert
job.started
runtime.signal.requested
policy.evaluated
```

Topic names should be specific enough to be useful in subscriptions and reports
but stable enough that plugin authors can depend on them.

## Publishing

Commandlets can publish events by yielding dictionaries from `run()`. The
runner stores those dictionaries under the commandlet's primary emitted topic.

For more explicit event-bus use, plugins should use `context.events`:

```python
context.events.publish("host.found", {"host": "127.0.0.1"})
```

The mediated API audits capability use such as `db.write:host.found`.

## Consuming

Pipeline input is scoped. A downstream run should consume upstream events from
the same pipeline and, when applicable, from the parent run it is attached to.

Plugins should use `context.events` for direct event access:

```python
for event in context.events.fetch(topic="host.found"):
    handle(event.payload)
```

This records `db.read:<topic>` capability usage and avoids raw database access.

## Replay and Attachment

Because events are durable, later commands can inspect or attach to historical
results:

```text
show host.found
pipeline attach run=2 since=beginning | http_probe
```

`since=` accepts the same selector vocabulary used by related runtime commands.
Unqualified `since=` and `until=` values default to time selectors.

## Framework Requests

Plugins do not directly perform interpreter-owned work such as console output,
alerts, paging, password prompts, or process execution. They publish framework
request events. The frontend or framework validates the request, performs or
denies it, then publishes an outcome event.

Examples:

```text
framework.console.output.requested -> console.output
framework.console.alert.requested  -> console.alert
framework.file.page.requested      -> console.page
framework.process.run.requested    -> process.run
```

Denied requests become:

```text
framework.request.denied
```

with the request event ID and denial reason in the payload.

This makes plugin behavior auditable and keeps terminal, GUI, and future web
frontends aligned around one event contract.

## Runtime Control Events

Runtime mutation is also event-driven. Commands such as `signal`, `pause`,
`resume`, `cancel`, and `kill` write structured control events. Commandlets that
support soft control read those events and emit outcome events describing what
they did.

Examples:

```text
runtime.signal.requested
runtime.signal.applied
runtime.signal.ignored
```

Already-recorded findings are append-only audit evidence. Runtime mutation
changes future work; it does not rewrite prior host, port, artifact, or finding
events.

## Artifacts and Notes

Large or sensitive outputs should be stored as artifacts, with metadata and
hashes recorded in the main event database. Artifact payloads may live in a
separate encrypted artifact database. Notes are timestamped events attached to
runs, pipelines, or jobs.

This gives Bywaf two useful integrity layers:

- the main event database records artifact metadata, hashes, and relationships;
- the artifact store preserves the actual attached content.

Verification should check both layers when possible.

## Provenance

Framework-level argument expansion, script loads, plugin loads, artifacts,
runtime names, and notes are events too. This is deliberate: the audit trail
should explain not just what a commandlet found, but also what inputs and
operator decisions led to that result.

Examples:

```text
framework.argument.expanded
plugin.loaded
script.loaded
note.attached
name.updated
artifact.attached
```

## Plugin Author Implications

Plugin authors should publish normalized facts as events, not just print text.
Console output is for the operator's live experience; events are the durable
record that later commandlets, reports, and GUIs consume.

Use `context.events` for normal event access. Use raw `context.db` only for
privileged framework/storage commandlets that explicitly declare and audit
`db.raw`.

Plugin integration type affects event provenance. Framework-native and
library-backed plugins usually publish events directly from Python objects.
External-process wrapper plugins should preserve tool command lines, return
codes, and output hashes in events or artifacts. Native/FFI plugins should
record enough boundary metadata to explain which compiled component produced
the event.
