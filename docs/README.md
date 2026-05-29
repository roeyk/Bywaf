# Documentation Roadmap

Start here when reading the Bywaf documentation. The docs are split by reader
role so operators, plugin authors, and maintainers can find the right level of
detail without reading every design note first.

Bywaf's current plugin model is commandlet-based. If you are coming from older
offensive frameworks, do not look for Veil-style modules, Metasploit-style
`info` dictionaries, or `run/exploit` entrypoints; use the current
`@commandlet` / `CommandletBase` API documented below.

## Quick Paths

- **New user:** [README](../README.md) -> [Install Guide](../INSTALL.md) ->
  [Usage Guide](../USAGE.md) ->
  [FAQ](FAQ.md)
- **Operator:** [Terminology](TERMINOLOGY.md) -> [Runtime Model](RUNTIME_MODEL.md) ->
  [Event Model](EVENT_MODEL.md) -> [Reporting](REPORTING.md) ->
  [Framework Surface](FRAMEWORK_SURFACE.md)
- **Plugin author:** [Plugin Author Guide](plugin_author/README.md) ->
  [Plugin Fundamentals](plugin_author/fundamentals.md) ->
  [Commandlet API Reference](plugin_author/commandlet-api.md) ->
  [Plugin Packaging And Checking](plugin_author/packaging-and-checking.md)
- **Maintainer:** [Changelog](../CHANGELOG.md) -> [TODO](TODO.md) ->
  [Framework Development](FRAMEWORK_DEVELOPMENT.md) ->
  [Testing](TESTING.md) ->
  [Key Management](KEY_MANAGEMENT.md) -> [Design Notes](DESIGN.md)

## Core References

- [Terminology](TERMINOLOGY.md): shared vocabulary for jobs, steps, pipelines,
  events, topics, commandlets, plugins, capabilities, local IDs, and serials.
- [Runtime Model](RUNTIME_MODEL.md): runtime entities, lifecycle,
  foreground/background execution, control signals, and variable snapshots.
- [Event Model](EVENT_MODEL.md): event rows, shared topic contracts, replay,
  framework requests, artifacts, notes, and provenance.
- [Shared Event Contracts](plugin_author/event-contracts.md): normalized
  plugin result topics such as `host.found`, `port.open`, and `http.endpoint`.
- [Finding And Report Model](FINDING_MODEL.md): facts, finding candidates,
  normalized finding payloads, deduplication, and the `report` inbox.
- [Reporting](REPORTING.md): operator workflow for `report`, grouping,
  scoped views, and accepted/deferred/rejected review state.
- [Persistence Model](PERSISTENCE_MODEL.md): event, runtime, artifact,
  maintenance, and variable store contracts.
- [Save/Export Model](SAVE_EXPORT_MODEL.md): when commands use `save`,
  `load`, `export`, `import`, or `archive`.
- [Install Guide](../INSTALL.md): OS dependency blocks, venv setup, package
  installation, optional plugin dependencies, and release package builds.
- [Capability Model](CAPABILITY_MODEL.md): capability auditing, trust
  boundaries, policy direction, and plugin integration types.
- [Plugin Manifest Specification](MANIFEST_SPECIFICATION.md): exact sidecar
  TOML schema, manifest generation, validation behavior, and boundaries.
- [Framework Surface](FRAMEWORK_SURFACE.md): enumerated base resources,
  including capabilities, trigger rules, plugin data topics, and framework
  audit/control topics.
- [Framework Development](FRAMEWORK_DEVELOPMENT.md): package map, core control
  flow, common change paths, and focused development checks.
- [Testing](TESTING.md): project-level test map for plugins, framework code,
  package builds, metrics, and manual validation.
- [Architecture Metrics](ARCHITECTURE_METRICS.md): dependency, size, fan-in,
  fan-out, and cycle checks for refactoring decisions.
- [Output Subjects And Theme Styles](plugin_author/output-subjects-and-styles.md):
  semantic output subjects, syntax-highlight styling, and report/table theme
  variables.

## Authoring And Operations

- [Plugin Author Guide](plugin_author/README.md): short entry point for the
  plugin author documentation set.
- [Plugin Fundamentals](plugin_author/fundamentals.md): plugin types, manifests,
  current API, arguments/options, and small examples.
- [Commandlet API Reference](plugin_author/commandlet-api.md): command specs, parsing,
  rendering, event publishing, completion, runtime context, and defaults.
- [Vulnerability Plugin Guide](plugin_author/vulnerability-plugins.md): vulnerability
  plugin layout, finding packaging, and skeleton intent.
- [Plugin Packaging And Checking](plugin_author/packaging-and-checking.md): loading,
  packaging, AI-assisted development, checker usage, and catalog signing.
- [Plugin Testing And Guidelines](plugin_author/testing-and-guidelines.md): plugin
  tests and practical implementation guidance.
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
