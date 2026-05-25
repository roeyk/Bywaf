# Persistence Model

Bywaf is local-first and SQLite remains the default storage implementation.
The persistence model is still deliberately split into higher-level store
contracts so framework code does not depend on SQLite details everywhere.

## Document Index

- [Store Contracts](#store-contracts)
- [Plugin Boundary](#plugin-boundary)
- [Backend Direction](#backend-direction)

## Store Contracts

`EventStoreProtocol` describes the durable event bus and audit log. It covers
event publication, scoped event fetches, polling, topic discovery, recent event
tailing, serial lookup, and event queries by job, step (`run=`), pipeline, or serial.
Today this is implemented by `bywaf.db.EventStore`.

`RuntimeStoreProtocol` describes runtime metadata for jobs, pipelines, steps,
local IDs, durable serials, cancellation requests, runtime names, variable
snapshots, and artifact counts. Today this is also implemented by
`bywaf.db.EventStore`; the contract exists because this metadata is not the
same thing as the event stream.

`ArtifactStoreProtocol` describes artifact body storage. It covers attaching
files, retrieving artifacts, listing by provenance selectors, replacing
artifact bodies, deleting artifacts, and verifying hashes and sizes. Today this
is implemented by `bywaf.artifacts.ArtifactStore`.

`MaintenanceStoreProtocol` describes privileged storage maintenance operations
such as checkpoint, vacuum, encryption status, rekey, and table counts. These
operations are intentionally separate from normal plugin event and artifact
usage.

`VariableStoreProtocol` describes session variable storage used by config,
completion, defaults, and per-step variable snapshots.

## Plugin Boundary

Normal commandlets should prefer mediated APIs:

- `context.events` for publishing, fetching, querying, and following events;
- `context.artifacts` for attaching files as auditable artifacts;
- `context.vars` for scoped commandlet variables;
- `context.process` for audited external process execution.

`context.db` and `context.require_db()` are privileged raw access paths for
framework and high-trust storage/runtime commandlets. They currently expose the
SQLite-backed `EventStore` because some internal commands still need concrete
maintenance and migration behavior.

Internal framework commandlets can use narrower store accessors when they need
more authority than the plugin-facing APIs but do not need raw SQL or
maintenance behavior:

- `context.event_store()` returns the event/audit contract;
- `context.runtime_store()` returns the job/step/pipeline metadata contract;
- `context.artifact_store()` returns the paired artifact body store;
- `context.maintenance_store()` returns maintenance operations and is audited
  as raw DB access.

Runtime commandlets should use these role-specific accessors instead of
`require_db()` unless they truly need raw storage behavior. The storage `db`
commandlet remains the primary raw maintenance user.

## Backend Direction

This model does not remove SQLite and does not require PostgreSQL, Redis,
Kafka, or a remote service. It gives Bywaf a clear boundary for future work:

- a PostgreSQL event store can implement the event and runtime contracts;
- an S3 or filesystem blob store can implement the artifact contract;
- a remote or synchronized deployment can preserve the same commandlet-facing
  APIs while changing the underlying storage.

Future storage work should migrate framework call sites toward these contracts
before adding non-SQLite backends.
