# Documentation Roadmap

Start here when reading the Bywaf documentation. The docs are split by reader
role so operators, plugin authors, and maintainers can find the right level of
detail without reading every design note first.

## Quick Paths

- **New user:** [README](../README.md) -> [Usage Guide](../USAGE.md) ->
  [FAQ](FAQ.md)
- **Operator:** [Terminology](TERMINOLOGY.md) -> [Runtime Model](RUNTIME_MODEL.md) ->
  [Event Model](EVENT_MODEL.md) -> [Framework Surface](FRAMEWORK_SURFACE.md)
- **Plugin author:** [Plugin Author Guide](PLUGIN_AUTHOR_GUIDE.md) ->
  [Plugin Manifest Specification](MANIFEST_SPECIFICATION.md) ->
  [Capability Model](CAPABILITY_MODEL.md) -> [Framework Surface](FRAMEWORK_SURFACE.md)
- **Maintainer:** [Changelog](../CHANGELOG.md) -> [TODO](TODO.md) ->
  [Key Management](KEY_MANAGEMENT.md) -> [Design Notes](DESIGN.md)

## Core References

- [Terminology](TERMINOLOGY.md): shared vocabulary for jobs, runs, pipelines,
  events, topics, commandlets, plugins, capabilities, local IDs, and serials.
- [Runtime Model](RUNTIME_MODEL.md): runtime entities, lifecycle,
  foreground/background execution, control signals, and variable snapshots.
- [Event Model](EVENT_MODEL.md): event rows, topics, replay, framework
  requests, artifacts, notes, and provenance.
- [Finding And Report Model](FINDING_MODEL.md): facts, finding candidates,
  normalized finding payloads, deduplication, and the `report` inbox.
- [Persistence Model](PERSISTENCE_MODEL.md): event, runtime, artifact,
  maintenance, and variable store contracts.
- [Save/Export Model](SAVE_EXPORT_MODEL.md): when commands use `save`,
  `load`, `export`, `import`, or `archive`.
- [Capability Model](CAPABILITY_MODEL.md): capability auditing, trust
  boundaries, policy direction, and plugin integration types.
- [Plugin Manifest Specification](MANIFEST_SPECIFICATION.md): exact sidecar
  TOML schema, manifest generation, validation behavior, and boundaries.
- [Framework Surface](FRAMEWORK_SURFACE.md): enumerated base resources,
  including capabilities, trigger rules, plugin data topics, and framework
  audit/control topics.

## Authoring And Operations

- [Plugin Author Guide](PLUGIN_AUTHOR_GUIDE.md): commandlets, manifests,
  capabilities, triggers, plugin signing, catalog trust, completion metadata,
  and packaging expectations.
- [Plugin Skeletons](plugin_skeletons/README.md): copyable plugin layouts for
  minimal native, vulnerability, library-backed vulnerability,
  process-wrapped vulnerability, and service trigger-provider plugins.
- [Key Management](KEY_MANAGEMENT.md): maintainer controls for official
  signing keys, public verification keys, rotation, overlap, retirement, and
  emergency revocation.
- [Save/Export Model](SAVE_EXPORT_MODEL.md): operator-facing file verb
  semantics across config, history, scripts, DBs, artifacts, bundles, keys, and
  projects.
- [FAQ](FAQ.md): common task examples and operational answers.
- [Goals](GOALS.md): project direction and non-goals.

## Diagrams

- [System Block Diagram](SYSTEM_BLOCK_DIAGRAM.pdf): live runtime flow and
  durable data flow through the system.
- [System Dataflow Diagram](SYSTEM_DATAFLOW_DIAGRAM.pdf): command input,
  event, artifact, audit, request, and report data movement.

## Planning

- [TODO](TODO.md): current release marker and next testing-release roadmap.
- [Design Notes](DESIGN.md): evolving framework design decisions.
