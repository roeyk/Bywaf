# Storage Backend Contract

Bywaf currently ships SQLite as the production storage backend. The backend
boundary is intentionally small enough that a future Postgres adapter can be
implemented without changing plugin code.

## Current Boundary

- `bywaf.db.EventStore` is the public event/runtime store facade.
- `bywaf.db.backends.DatabaseBackend` owns connection setup and schema
  initialization.
- `bywaf.db.backends.DatabaseBackendCapabilities` names backend traits that
  affect operator behavior: local file semantics, at-rest encryption, and
  backup support.
- `bywaf.stores` defines the event, runtime, artifact, maintenance, and
  variable store protocols callers should depend on.

## Backend Requirements

A non-SQLite backend must preserve:

- durable monotonically increasing event ids;
- append-oriented event publication with topic, source, payload, and runtime
  scope columns;
- job, pipeline, run, trigger, variable, secret, and maintenance APIs exposed
  by `EventStore`;
- short-lived connection behavior suitable for foreground and background work;
- deterministic JSON payload serialization;
- capability-audited event access through framework services;
- explicit migration or schema initialization behavior;
- artifact provenance compatibility with the main event store.

## Postgres Next Step

The next implementation step is to add a Postgres backend module that implements
`DatabaseBackend`, exposes `DatabaseBackendCapabilities(name="postgres", ...)`,
and passes the existing store protocol tests through a backend-parametrized
fixture. SQLite should remain the default local backend.
