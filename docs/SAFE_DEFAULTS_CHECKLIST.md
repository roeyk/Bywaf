# Safe Defaults Checklist

Use this checklist before expanding bundled plugin coverage or tagging a
release that changes security-sensitive behavior.

## Operator Visibility

- Risky behavior has an operator-visible command, option, or manifest trait.
- Developer bypass flags name what protection they disable.
- New network-facing plugins document target scope, timeout, and rate/limit
  behavior.
- Long-running work can be inspected with `job`, `pipeline`, `step`, and
  relevant inventory views.

## Capabilities And Database Actions

- Commandlets declare exact capabilities in Python metadata and TOML manifests.
- Effective `database.actions.*` metadata distinguishes view, write, review,
  and manage behavior.
- Bundled plugins run under strict capability enforcement in tests where
  practical.
- Raw database access is absent from ordinary plugins, or explicitly justified
  and audited as `db.raw`.

## Plugin And Schema Trust

- Plugin-owned event schemas are manifest TOML, not Python registration code.
- `consumes` and `emits` match commandlet behavior.
- Schema-backed events validate at runtime unless
  `global.schema.validation=off` is deliberately set for development.
- Filesystem plugin loading preserves the rule that manifest metadata is
  inspectable before plugin code runs.

## Process And Network Wrappers

- External tools are invoked with argv lists and `shell=False`.
- User-controlled paths cannot be interpreted as tool options.
- Timeouts, max-target controls, or other practical bounds exist.
- Raw stdout/stderr or equivalent evidence is retained where parser drift would
  affect operator trust.
- Process result events redact known secret values.

## Secrets

- Secret options are declared in manifests.
- Secret values do not appear in history, runtime rows, audit exports, process
  argv/env/stdout/stderr, rendered tables, or artifacts unless explicitly
  intended.
- Secret prompts and secret references are tested with redaction assertions.

## Artifacts And Exports

- Artifact writes record size, SHA-256, content type, and runtime provenance.
- Artifact inspection commands such as `artifact cat` are read-only and do not
  mutate evidence bodies or provenance.
- Exports avoid unexpected overwrite behavior and record what was exported.
- Evidence replacement preserves lineage or emits enough audit data to explain
  the previous and new artifact records.
- Bundle/export commands preserve evidence hashes.
- `artifact verify` or equivalent integrity checks cover new artifact paths.

## Destructive Or Live Control

- Stop, kill, delete, replace, import, export, and key-management paths have
  clear command names and tests.
- Live-control commands prefer high-level verbs such as `pause`, `resume`,
  `stop`, and `end`; low-level `signal` behavior is documented.
- Plugins should not receive the full pipeline plan when a narrower ID/event
  boundary is enough.

## Release Gate

Before release:

1. Run focused tests for touched plugins and framework services.
2. Run the full test suite.
3. Run architecture/documentation metrics and inspect dependency cycles,
   broken links, hub growth, and security-surface changes.
4. Run plugin checker tests for manifest/capability/schema changes.
5. Run package/version alignment checks when package metadata changed.
6. Update changelog and tracker items with the actual risk/impact.
