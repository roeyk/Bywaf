# Bywaf Event Model

Bywaf uses SQLite as an append-oriented event store. Commandlets cooperate by
publishing and consuming structured events instead of passing ad hoc files or
terminal output between tools.

## Document Index

- [Event Rows](#event-rows)
- [Topics](#topics)
- [Shared Event Contracts](#shared-event-contracts)
- [Publishing](#publishing)
- [Consuming](#consuming)
- [Replay and Attachment](#replay-and-attachment)
- [Framework Requests](#framework-requests)
- [Runtime Control Events](#runtime-control-events)
- [Artifacts and Notes](#artifacts-and-notes)
- [Provenance](#provenance)
- [Plugin Author Implications](#plugin-author-implications)

## Event Rows

An event row records:

- numeric event ID;
- topic;
- JSON payload;
- source commandlet or framework component;
- timestamp;
- pipeline ID;
- step ID;
- parent step ID.

The row scope is authoritative. Payloads may repeat fields such as
`pipeline_id` or `command_run_id` for convenience, but the database columns are
the canonical runtime scope.

## Topics

A topic names what happened.

Examples:

```text
host.found
name.resolved
port.open
http.endpoint
artifact.imported
artifact.attached
framework.console.alert.requested
console.alert
job.started
runtime.signal.requested
policy.evaluated
```

Topic names should be specific enough to be useful in subscriptions and reports
but stable enough that plugin authors can depend on them.

## Shared Event Contracts

Bywaf treats common topics as shared contracts. The database still stores
append-only JSON events, but a shared topic promises a stable payload shape that
views, reports, follow-up plugins, and future frontends can depend on.

This is the normalized layer above tool-native output:

```text
raw/private event       = tool-specific observation or detail
shared/framework event  = normalized fact other tools can use
finding.candidate       = reportable security interpretation
```

For example, an SMB plugin can preserve scanner-specific ACL detail in a
private topic such as `smb_enum.raw_share_acl`, emit normalized share facts as
`smb.share.found`, and emit `finding.candidate` only for risky shares.

Framework-known contracts currently live in `bywaf.event_contracts`. The first
shared topics are:

| Topic | Required fields | Purpose |
| --- | --- | --- |
| `host.found` | `host` | A host was observed alive or reachable. |
| `name.resolved` | `name`, `host` | A name resolved to a concrete address. |
| `port.open` | `host`, `port`, `protocol` | A network port was observed open. |
| `http.endpoint` | `url`, `host`, `port`, `scheme` | A reachable HTTP or HTTPS endpoint. |
| `smb.share.found` | `host`, `share` | An SMB share was observed on a host. |
| `finding.candidate` | `title`, `class` | A normalized finding-shaped observation. |
| `artifact.attached` | `artifact_id`, `name`, `content_type`, `sha256`, `size` | Artifact metadata attached to provenance. |

Plugin-private topics remain free-form. A plugin only needs to align with a
framework contract when other plugins or framework views should understand that
data. If data is private evidence, use a plugin-specific topic or artifact. If
data is security-reportable, also map it into `finding.candidate`.

## Publishing

Commandlets can publish events by yielding dictionaries from `run()`. The
runner stores those dictionaries under the commandlet's primary emitted topic.

For more explicit event-bus use, plugins should use `context.events`:

```python
context.events.publish("host.found", {"host": "127.0.0.1"})
```

The mediated API audits capability use such as `db.write:host.found`.

Some commandlets publish supporting provenance topics directly. For example,
`hostscanner` emits `name.resolved` when a DNS name is resolved into concrete
addresses, then emits `host.found` only for live hosts discovered by nmap.

## Consuming

Pipeline input is scoped. A downstream step should consume upstream events from
the same pipeline and, when applicable, from the parent step it is attached to.

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
event host.found
pipeline attach 1 http_probe step=2 since=beginning
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
steps, pipelines, or jobs.

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
artifact.imported
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
