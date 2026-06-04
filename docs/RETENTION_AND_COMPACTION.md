# Retention And Compaction

Bywaf stores assessment history as durable events plus paired artifact records.
Retention is therefore an evidence lifecycle decision before it is a database
maintenance decision. The default policy is conservative: preserve project
history unless an operator explicitly exports, archives, or deletes a scoped
piece of evidence.

This document defines the current policy boundary. It does not introduce an
automatic pruning command.

## Current Recommendation

For normal projects:

- keep the event database and artifact database together as an integrity pair;
- split unrelated clients, assessments, or authorization windows into separate
  project databases;
- use `audit export`, `artifact export`, and `bundle export` for scoped
  deliverables;
- use `db export` or project archive workflows for whole-project preservation;
- use `db checkpoint` before copying database files outside Bywaf;
- use `db vacuum` only after explicit deletions or future compaction work.

Do not use retention or compaction as a routine performance workaround. Current
SQLite benchmarks show no need for automatic pruning, batching, or a backend
split for measured local-first workloads.

## Preservation Classes

### Never Auto-Pruned

These records are audit or chain-of-custody material. Bywaf should not remove
them automatically:

- command history that explains what the operator asked Bywaf to do;
- job, pipeline, and step lifecycle events;
- capability, policy, setup, plugin trust, and secret-handling audit events;
- framework request and denial records;
- notes attached by the operator;
- finding review events, including accept, defer, reject, and confirmation
  decisions;
- report, bundle, audit export, database export, and artifact export events;
- artifact provenance events such as `artifact.imported`,
  `artifact.attached`, `artifact.replaced`, `artifact.removed`, and
  `artifact.exported`.

Removing these records weakens the ability to explain how evidence was
collected, reviewed, handed off, or deleted.

### Preserved Unless Explicitly Scoped

These records may become large, but they still often explain assessment state:

- normalized facts such as hosts, ports, routes, HTTP endpoints, banners,
  screenshots, certificates, service detections, and web fingerprints;
- vulnerability and finding candidate records;
- plugin-private raw observation topics;
- runtime progress and operational diagnostic events.

Future compaction may allow an operator to archive or summarize selected
records in this class, but only after an explicit scope and export decision.

### Artifact Bodies And Metadata

Artifact bodies live in the artifact database, while artifact metadata and
provenance live in the main event database. Treat those files as a pair.

An artifact body must not be pruned while retained event history, bundles, or
reports still reference it. If an operator explicitly removes an artifact,
Bywaf should keep the removal event and enough metadata to explain what was
removed: artifact ID, name, content type, size, hash, scope, and timestamp.

## Required Archive Step

Any future destructive compaction command should require an archive or export
step before deleting data. Acceptable preservation paths include:

- `db export file=...` for a whole event-database snapshot;
- encrypted `audit export file=... --format sqlite --encrypt` for selected or
  full audit preservation;
- `artifact export ...` for selected artifact bodies;
- `bundle export name=... file=...` for curated handoff evidence;
- project archive/export workflows when a complete restorable project package
  is available.

The command should record audit events before and after destructive work. The
pre-event should include the requested scope, preservation target, and expected
classes of data affected. The post-event should include counts, hashes or
archive identifiers where available, and any failures.

## Future Command Shape

If Bywaf later grows a compaction command, it should be explicit and scoped.
Candidate shapes:

```text
retention plan project=<name> older-than=180d
retention archive project=<name> file=client-a.bywaf-archive
retention compact project=<name> older-than=180d --require-archive file=client-a.bywaf-archive
```

The first implementation should prefer a dry-run plan over immediate deletion.
It should show matched event classes, artifact impact, bundle/report impact, and
the exact follow-up command needed to perform the destructive step.

Avoid background or policy-driven deletion until the operator model is mature.
Bywaf should not silently remove assessment history because a size or age
threshold was crossed.

## When To Split Instead Of Compact

Split into a new project database when:

- the work is for a different client, scope, or authorization window;
- old evidence should remain available but no longer belongs in active views;
- a project is large because it combines unrelated assessments;
- operators need separate archive, encryption, retention, or handoff policies.

Compact only when the operator can clearly state which historical material no
longer needs to remain queryable in the active project and has preserved the
material elsewhere.

## Current Closeout Decision

Current behavior remains:

- no automatic event pruning;
- no automatic artifact pruning;
- no automatic checkpoint or vacuum schedule;
- no single-writer queue or batching layer for retention reasons;
- explicit export/archive before any future destructive compaction;
- explicit `artifact remove` or `artifact replace` for artifact mutation, with
  retained provenance events.

This is sufficient for the current measured scale. Reopen implementation work
only when a real project shows operator-visible database size, query latency,
export latency, or evidence lifecycle pressure that project splitting and
explicit export/archive do not address.
