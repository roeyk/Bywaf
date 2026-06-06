# Documentation Paths

Documentation Paths are curated reading sequences for different Bywaf reader
roles. They are shorter than the full documentation index and are meant to help
readers reach a useful working understanding without reading every document in
the repository.

The paths are ordered by authority: start with documented project intent,
architecture, workflow, and public contracts before relying on examples or
source-code inference. Source code is still the implementation truth, but these
paths show where the intended abstractions and constraints are documented.

**Audience**

This document is for readers choosing where to start: new users, authorized
operators, plugin developers, external scanner adapter authors, framework
developers, security reviewers, packagers, release maintainers, and
documentation maintainers.

**Related Documents**

- [Documentation Roadmap](README.md): full documentation index and broad
  reference map.
- [Operator Quickstart](OPERATOR_QUICKSTART.md): first hands-on operator path.
- [Plugin Author Guide](plugin_author/README.md): entry point for plugin
  developers.
- [Framework Development](FRAMEWORK_DEVELOPMENT.md): maintainer-oriented code
  and workflow map.
- [Testing](TESTING.md): validation commands and package/test matrix.
- [Security Audit](SECURITY_AUDIT.md): security review scope and release-gate
  checks.
- [Performance](PERFORMANCE.md): measurement, optimization, and runtime
  performance guidance.

## Contents

- [New User Or Evaluator](#new-user-or-evaluator)
- [Authorized Operator Or Pentester](#authorized-operator-or-pentester)
- [Plugin Developer](#plugin-developer)
- [External Scanner Adapter Developer](#external-scanner-adapter-developer)
- [Framework Developer](#framework-developer)
- [Security Reviewer](#security-reviewer)
- [Packager Or Release Maintainer](#packager-or-release-maintainer)
- [Documentation Maintainer](#documentation-maintainer)

## New User Or Evaluator

Use this path to understand what Bywaf is, install it, and run a safe first
workflow.

Read in order:

1. [README](../README.md)
2. [Install Guide](../INSTALL.md)
3. [Operator Quickstart](OPERATOR_QUICKSTART.md)
4. [Usage Guide](../USAGE.md)
5. [FAQ](FAQ.md)

Optional deep dives:

- [Goals](GOALS.md)
- [Bundled Plugin Manual](BUNDLED_PLUGIN_MANUAL.md)
- [Documentation Roadmap](README.md)

After this path, you should be able to install Bywaf, discover commands, run a
safe local workflow, inspect results, and know which deeper docs match your
next task.

## Authorized Operator Or Pentester

Use this path to run authorized assessments while preserving evidence,
provenance, and review state.

Read in order:

1. [Terminology](TERMINOLOGY.md)
2. [Operator Quickstart](OPERATOR_QUICKSTART.md)
3. [Runtime Model](RUNTIME_MODEL.md)
4. [Bundled Plugin Manual](BUNDLED_PLUGIN_MANUAL.md)
5. [Finding And Report Model](FINDING_MODEL.md)
6. [Reporting](REPORTING.md)
7. [Security Audit](SECURITY_AUDIT.md)
8. [Retention And Compaction](RETENTION_AND_COMPACTION.md)

Optional deep dives:

- [Event Model](EVENT_MODEL.md)
- [Save/Export Model](SAVE_EXPORT_MODEL.md)
- [Performance](PERFORMANCE.md)

After this path, you should be able to structure a project, run safe scans,
follow jobs, review findings, preserve artifacts, export evidence, and avoid
mixing unrelated assessments into one audit history.

## Plugin Developer

Use this path to build commandlet-based Bywaf plugins that are safe, testable,
and compatible with the framework's event and capability model.

Read in order:

1. [Plugin Author Guide](plugin_author/README.md)
2. [Plugin Fundamentals](plugin_author/fundamentals.md)
3. [Commandlet API Reference](plugin_author/commandlet-api.md)
4. [Shared Event Schemas](plugin_author/event-schemas.md)
5. [Capability Model](CAPABILITY_MODEL.md)
6. [Plugin Manifest Specification](MANIFEST_SPECIFICATION.md)
7. [Plugin Packaging And Checking](plugin_author/packaging-and-checking.md)
8. [Plugin Testing And Guidelines](plugin_author/testing-and-guidelines.md)

Optional deep dives:

- [Plugin Author Workflow](plugin_author/workflow.md)
- [Vulnerability Plugin Guide](plugin_author/vulnerability-plugins.md)
- [Plugin Skeletons](plugin_skeletons/README.md)

After this path, you should be able to create a plugin, define commandlets,
publish normalized events, declare capabilities, write a sidecar manifest, run
plugin checks, and package or load the plugin locally.

## External Scanner Adapter Developer

Use this path when wrapping external tools while preserving raw evidence and
emitting normalized Bywaf facts or findings.

Read in order:

1. [Plugin Author Guide](plugin_author/README.md)
2. [Wrapper Robustness](plugin_author/wrapper-robustness.md)
3. [Shared Event Schemas](plugin_author/event-schemas.md)
4. [Finding And Report Model](FINDING_MODEL.md)
5. [Capability Model](CAPABILITY_MODEL.md)
6. [Plugin Packaging And Checking](plugin_author/packaging-and-checking.md)
7. [Performance](PERFORMANCE.md)

Optional deep dives:

- [Vulnerability Plugin Guide](plugin_author/vulnerability-plugins.md)
- [Security Audit](SECURITY_AUDIT.md)
- [Save/Export Model](SAVE_EXPORT_MODEL.md)

After this path, you should be able to run an external scanner through a Bywaf
adapter, retain raw stdout/stderr or native output as artifacts, parse outputs
with fixture coverage, and emit compact normalized results.

## Framework Developer

Use this path to change Bywaf internals without losing the framework's runtime,
event, persistence, testing, and safety boundaries.

Read in order:

1. [Terminology](TERMINOLOGY.md)
2. [Framework Development](FRAMEWORK_DEVELOPMENT.md)
3. [Event Model](EVENT_MODEL.md)
4. [Runtime Model](RUNTIME_MODEL.md)
5. [Persistence Model](PERSISTENCE_MODEL.md)
6. [Testing](TESTING.md)
7. [Architecture Metrics](ARCHITECTURE_METRICS.md)
8. [Performance](PERFORMANCE.md)

Optional deep dives:

- [Framework Surface](FRAMEWORK_SURFACE.md)
- [Storage Backends](STORAGE_BACKENDS.md)
- [Development Workflow](DEVELOPMENT_WORKFLOW_README.md)
- [Design Notes](DESIGN.md)

After this path, you should be able to locate core subsystems, make focused
changes, understand event/runtime contracts, run validation, and use metrics to
decide when refactoring is justified.

## Security Reviewer

Use this path to review Bywaf's safety model, trust boundaries, plugin
behavior, storage assumptions, and release gates.

Read in order:

1. [Security Audit](SECURITY_AUDIT.md)
2. [Safe Defaults Checklist](SAFE_DEFAULTS_CHECKLIST.md)
3. [Capability Model](CAPABILITY_MODEL.md)
4. [Key Management](KEY_MANAGEMENT.md)
5. [Plugin Manifest Specification](MANIFEST_SPECIFICATION.md)
6. [Wrapper Robustness](plugin_author/wrapper-robustness.md)
7. [Retention And Compaction](RETENTION_AND_COMPACTION.md)
8. [Testing](TESTING.md)

Optional deep dives:

- [Event Model](EVENT_MODEL.md)
- [Save/Export Model](SAVE_EXPORT_MODEL.md)
- [Storage Backends](STORAGE_BACKENDS.md)

After this path, you should be able to evaluate safe defaults, plugin trust,
capability boundaries, artifact handling, database limits, wrapper risks, and
release validation expectations.

## Packager Or Release Maintainer

Use this path to build, test, and verify release artifacts across supported
installation paths.

Read in order:

1. [Install Guide](../INSTALL.md)
2. [Testing](TESTING.md)
3. [Key Management](KEY_MANAGEMENT.md)
4. [Plugin Packaging And Checking](plugin_author/packaging-and-checking.md)
5. [Safe Defaults Checklist](SAFE_DEFAULTS_CHECKLIST.md)
6. [Changelog](../CHANGELOG.md)

Optional deep dives:

- [Security Audit](SECURITY_AUDIT.md)
- [Framework Development](FRAMEWORK_DEVELOPMENT.md)
- [Performance](PERFORMANCE.md)

After this path, you should be able to build source, wheel, Debian, and RPM
artifacts; run package smoke tests; verify bundled plugin loading; manage
signing material; and prepare release notes.

## Documentation Maintainer

Use this path to keep Bywaf documentation navigable, role-aware, and aligned
with code behavior.

Read in order:

1. [Documentation Roadmap](README.md)
2. [Terminology](TERMINOLOGY.md)
3. [Development Workflow](DEVELOPMENT_WORKFLOW_README.md)
4. [Framework Development](FRAMEWORK_DEVELOPMENT.md)
5. [Architecture Metrics](ARCHITECTURE_METRICS.md)
6. [Testing](TESTING.md)
7. [Documentation Paths](DOCUMENTATION_PATHS.md)

Optional deep dives:

- [Operator Quickstart](OPERATOR_QUICKSTART.md)
- [Plugin Author Guide](plugin_author/README.md)
- [Event Model](EVENT_MODEL.md)
- [Capability Model](CAPABILITY_MODEL.md)

After this path, you should be able to maintain audience blocks, related
document links, role-based reading paths, terminology consistency, doc-impact
checks, and validation notes.
