# Framework Development

This guide is for contributors changing Bywaf itself. If you want to write a
plugin, start with `docs/plugin_author/README.md` instead; plugin authors should
not need to learn the whole framework internals first.

Bywaf is a commandlet framework built around a few stable ideas:

- command text is parsed into commandlet invocations;
- commandlets emit structured events;
- jobs, pipelines, and steps provide runtime provenance;
- reports, artifacts, bundles, and view commands render or package stored
  framework state;
- plugin manifests describe commandlets without importing executable plugin
  code.

## Contents

- [Fast Orientation](#fast-orientation)
- [Package Map](#package-map)
  - [CLI And REPL](#cli-and-repl)
  - [Command Parsing](#command-parsing)
  - [Runner](#runner)
  - [Plugins And Registry](#plugins-and-registry)
  - [Persistence](#persistence)
  - [Findings, Reports, And Artifacts](#findings-reports-and-artifacts)
  - [Display, Subjects, And Syntax Highlighting](#display-subjects-and-syntax-highlighting)
  - [Configuration, Secrets, And Preferences](#configuration-secrets-and-preferences)
- [Common Change Paths](#common-change-paths)
  - [Add Or Change A View Command](#add-or-change-a-view-command)
  - [Add A Runtime Selector](#add-a-runtime-selector)
  - [Promote A Plugin-Owned Event Schema](#promote-a-plugin-owned-event-schema)
  - [Refactor A Large Module](#refactor-a-large-module)
  - [Change Plugin Contracts](#change-plugin-contracts)
- [Testing Expectations](#testing-expectations)

## Fast Orientation

Read these first when changing core behavior:

- `docs/TERMINOLOGY.md`: canonical vocabulary.
- `docs/RUNTIME_MODEL.md`: jobs, pipelines, steps, variables, and snapshots.
- `docs/EVENT_MODEL.md`: event rows, topics, replay, and provenance.
- `docs/CAPABILITY_MODEL.md`: capability audit and trust boundaries.
- `docs/ARCHITECTURE_METRICS.md`: how to choose refactor targets.

Then inspect the relevant package below.

## Package Map

### CLI And REPL

- `bywaf/__main__.py`: command-line entry point.
- `bywaf/app.py`: application facade that wires registry, project, database,
  runner, and shell behavior.
- `bywaf/repl/`: interactive shell commands, script loading, preferences,
  display, and command dispatch.
- `bywaf/completion/`: readline and prompt-toolkit completion.

The REPL is a frontend. It should avoid owning core behavior that would also
matter to scripts, future GUI/web frontends, or API callers.

### Command Parsing

- `bywaf/command/parser/`: parses command text into pipeline and invocation
  structures.
- `bywaf/command/names.py`: shared command/action constants.

Parser changes are high-impact. Add regression tests for quoting, comments,
selectors, pipelines, at-file syntax, variables, and framework-owned selectors.

### Runner

- `bywaf/runner/core.py`: `Runner` facade and job/pipeline orchestration.
- `bywaf/runner/stages.py`: one pipeline step lifecycle, argument expansion,
  redaction, commandlet execution, and emitted event persistence.
- `bywaf/runner/context.py`: runtime context construction, variable snapshots,
  replay selectors, and step identity.
- `bywaf/runner/jobs.py`: foreground/background job lifecycle and child-process
  entry points.
- `bywaf/runner/runtime_events.py`: small helpers for framework runtime events.

The runner is the control plane. Keep it narrow: orchestration belongs here,
domain rendering and plugin-specific behavior do not.

### Plugins And Registry

- `bywaf/plugin/`: commandlet API, `CommandContext`, process/services helpers,
  and plugin-facing framework interfaces.
- `bywaf/registry/`: plugin discovery, provider paths, aliases, manifests,
  variable scopes, and trigger ownership.
- `bywaf/plugins/`: bundled commandlets organized by provider path.
- `docs/plugin_author/`: plugin author-facing contracts.

Manifest metadata should describe plugin shape before import. Runtime plugin
code should go through framework APIs for events, artifacts, processes, and
operator-facing output wherever possible.

### Persistence

- `bywaf/db/`: SQLite-backed store facade and focused mixins for events, jobs,
  runtime state, artifacts, secrets, triggers, and maintenance.
- `bywaf/stores.py`: protocol surfaces used to keep callers from depending on
  concrete SQLite implementation details.
- `docs/STORAGE_BACKENDS.md`: backend contract and the next Postgres adapter
  implementation step.

Persistence code is shared by foreground and background work. Preserve
multiprocess behavior and avoid hidden per-process state.

### Findings, Reports, And Artifacts

- `bywaf/finding/`: normalized finding payloads, grouping, severity, taxonomy,
  and subject metadata.
- `bywaf/plugins/analysis/report.py`: operator reporting commandlet.
- `bywaf/plugins/analysis/report_render.py`: report table rendering helpers.
- `bywaf/artifacts.py` and `bywaf/plugins/runtime/artifact*`: artifact storage,
  selectors, verification, and export/import workflows.

Findings are append-only evidence. Review decisions are emitted as events, not
mutations of original findings.

### Display, Subjects, And Syntax Highlighting

- `bywaf/style.py`: parses terminal style strings, RGB/256-color values,
  structured foreground/background settings, and subject style inheritance.
- `bywaf/repl/display/`: REPL-facing rendering helpers for events, variables,
  expansion previews, runtime tables, and pager output.
- `bywaf/completion/prompt/`: live prompt syntax highlighting for comments,
  quoted strings, assignment values, and `$VARIABLE` references.
- `docs/plugin_author/output-subjects-and-styles.md`: canonical subject and
  theme contract for plugin authors and renderer maintainers.

Renderers should style by semantic subject (`host`, `serial`, `finding.title`,
`table.header`) instead of hard-coding colors. Broad subjects provide defaults;
more specific subjects override them when nested in strings, tables, or report
details.

### Configuration, Secrets, And Preferences

- `bywaf/config/`: project/global config loading, canonicalization, and
  resource paths.
- `bywaf/secret/`: secret references, redaction, fingerprints, and prompt
  handling.
- `bywaf/keyring/`: signing and key-management support.
- `bywaf/repl/preferences.py` and `bywaf/repl/themes.py`: operator preferences
  and display themes.

Secrets must never be displayed directly. Redacted values should preserve enough
fingerprint provenance for audit without exposing reusable handles.

Secret input mode is deliberately layered:

- `block` is a prompt-toolkit editor feature that keeps typed text out of the
  submitted command buffer and shows a redacted inline block.
- `askpass`, `getpass`, and `plain` are value readers used after an explicit
  empty secret assignment such as `set --secret name=`.
- `auto` is the default. It resolves to desktop askpass when available and to
  block mode otherwise.

Askpass should warn and fall back to terminal input when a graphical helper is
unavailable. Canceled prompts should remain cancellations. Rendered variables,
history, runtime output, and audit surfaces must keep redacted fingerprint
labels rather than cleartext.

## Common Change Paths

### Add Or Change A View Command

1. Update the commandlet or REPL command.
2. Use selector-style filters such as `job=`, `pipeline=`, `step=`, `host=`,
   `topic=`, and `sort=`.
3. Keep rendering in a rendering helper when the command grows.
4. Add tests for selectors, empty output, and table shape.

### Add A Runtime Selector

1. Update parser or command dispatch if the selector is framework-owned.
2. Add shared matching logic rather than duplicating host/job/pipeline/step
   scans in each command.
3. Update completion.
4. Add tests across all view commands that should support it.

### Promote A Plugin-Owned Event Schema

Plugin-owned schemas are registered through manifest TOML so the framework can
inspect them before importing plugin Python. Promotion is different: it is a
framework maintainer decision to adopt a registered plugin schema as core shared
vocabulary.

Use this policy:

1. Require evidence that the schema is useful beyond one plugin, such as reuse
   by multiple commandlets, inventory/report views, bundles, GUI/API work, or
   follow-up plugins.
2. Keep the same topic name and version lineage when the topic name and field
   meanings are sound. Promotion should usually change ownership, not event
   identity.
3. Create a new framework topic only when the plugin-owned topic name or field
   semantics are wrong enough to mislead future consumers.
4. Treat aliases as temporary migration bridges, not permanent vocabulary.
5. Move the canonical schema into `bywaf/event/schemas.py` and, when useful,
   add a framework-owned object class in `bywaf/event/schema_objects.py`.
6. Update `docs/EVENT_MODEL.md`, `docs/plugin_author/event-schemas.md`, and
   any inventory/report/result views that should treat the topic as first-class.
7. Add tests for validation, schema inspection, at least one producer, and at
   least one consumer/view.
8. Add a changelog note when promotion affects external plugin compatibility.

Plugin authors can register and use plugin-owned schemas without this process.
Promotion is only for schemas that Bywaf itself promises to keep stable.

### Parser And Completion Complexity Budget

Parser, completion, prompt UI, and app-dispatch changes are user-facing shell
contract changes. Keep them narrow and testable:

1. Treat a parser/completion defect as a contract bug. Add the smallest
   regression that captures the command shape, selector, variable expansion, or
   completion menu before changing behavior.
2. Split by responsibility when complexity grows: token parsing, command
   invocation assembly, variable expansion, completion providers, prompt UI
   rendering, and app-dispatch routing should stay separately reviewable.
3. Keep ordinary parser/completion source and test files below the 500-line
   review gate. When a changed file reaches the gate, split by functionality
   and aim for 300-400 line cohesive modules where practical.
4. Prefer tables, typed result objects, and focused provider classes over long
   branch ladders. Do not replace the parser broadly unless a focused defect or
   architectural metric supports the change.
5. Run `tests/app_dispatch`, `tests/registry_completion`, and
   `tests/test_completion_regression.py` for parser, completion, prompt UI, or
   app-dispatch changes.

### Refactor A Large Module

1. Run `python scripts/architecture_metrics.py --top 12 --churn`.
2. Pick modules with multiple signals, not just high LOC.
3. Add or identify focused regression tests first.
4. Split by responsibility: parsing, querying, rendering, lifecycle, storage,
   or data conversion.
5. Rerun the metrics and compare whether fan-out, complexity, or cycles
   improved.

### Change Plugin Contracts

1. Update plugin API or manifest schema.
2. Update `plugin_check`.
3. Update skeletons and `docs/plugin_author/`.
4. Add tests for both valid and invalid plugin examples.

## Testing Expectations

For the full testing map, including plugin tests, package smoke tests, manual
validation flows, and environment notes, see [Testing](TESTING.md).

Useful focused checks:

```bash
PYTHONPATH=. pytest -q tests/registry_completion tests/test_completion_regression.py
PYTHONPATH=. pytest -q tests/app_dispatch tests/test_resources_history_config.py
PYTHONPATH=. pytest -q tests/plugin_check tests/test_repo_exposure.py
PYTHONPATH=. pytest -q tests/test_report.py tests/finding
```

Use the architecture metrics report before and after non-trivial refactors:

```bash
python scripts/architecture_metrics.py --top 12
python scripts/architecture_metrics.py --top 12 --churn
```
