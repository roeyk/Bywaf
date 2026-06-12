# Bywaf Assistant Guide

This file is the repository-local startup guide for coding assistants. It
should contain the durable project conventions needed to get up to speed
without relying on private development notes, chat history, or machine-specific
paths.

Private handoff, tracker, action-log, and lessons-learned files may exist
outside this repository for the maintainer's own development workflow. Treat
those files as optional supplemental context when the user explicitly provides
or references them. Do not require them before working from this repository,
and do not commit local absolute paths to them.

On startup or restart, do not begin code development, edit repository files,
commit, push, or run a broad coding batch until the user explicitly clears you
to proceed. You may inspect repository state and relevant files for context.
After that inspection, state your next intended action and wait for the
go-ahead.

When a private action log is provided, use it as continuity for fresh
zero-knowledge context starts and restarts: it should summarize recent concrete
coding actions, major implementation decisions, commits, validation commands
and results, current work-goal management, and immediate follow-up state. It
should record when work starts on an item, when priorities change, when items
are reprioritized or shelved, and when items finish. It is not the source of
truth for durable design rationale or long-term priority sequencing.

Before editing code, committing, pushing, or running a broad coding batch,
inspect the repository state:

```bash
git status --short --branch
git diff --stat
git log --oneline -5
git log --oneline origin/main..HEAD
```

Then inspect the local files relevant to the task before editing. If there is
uncommitted work, assume it is intentional and read the relevant diffs before
touching those files.

The first working update should summarize branch/status, the latest local
commit, whether there is uncommitted or unpushed work, the applicable validation
guidance below, and the repository files inspected or planned for inspection.

Do not commit local machine paths, usernames, home directories, scratch
directories, secrets, tokens, keys, cookies, or other environment-specific
disclosure into this repository.

## Repository Orientation

Read the smallest set of repo-local files that explains the task before
editing. Good starting points are:

- General project context: `README.md`, `USAGE.md`, `docs/README.md`,
  `docs/GOALS.md`, and `docs/DESIGN.md`.
- Framework architecture: `docs/FRAMEWORK_SURFACE.md`,
  `docs/EVENT_MODEL.md`, `docs/CAPABILITY_MODEL.md`,
  `docs/RUNTIME_MODEL.md`, `docs/PERSISTENCE_MODEL.md`, and
  `docs/TERMINOLOGY.md`.
- Plugin authoring and checking: `docs/PLUGIN_AUTHOR_GUIDE.md`,
  `docs/MANIFEST_SPECIFICATION.md`, `docs/plugin_author/README.md`,
  `docs/plugin_author/fundamentals.md`,
  `docs/plugin_author/commandlet-api.md`,
  `docs/plugin_author/event-schemas.md`, and
  `docs/plugin_author/packaging-and-checking.md`.
- Findings, reports, artifacts, and evidence: `docs/FINDING_MODEL.md`,
  `docs/REPORTING.md`, `docs/SAVE_EXPORT_MODEL.md`, and relevant bundle or
  artifact tests.
- Architecture and testing practice: `docs/ARCHITECTURE_METRICS.md`,
  `docs/TESTING.md`, `pyproject.toml`, and the focused tests matching the
  touched surface.
- User-facing behavior: `docs/OPERATOR_QUICKSTART.md`, `USAGE.md`, relevant
  command modules under `bywaf/plugins/`, and user-flow scripts under
  `tests/user_flows/`.

For implementation work, inspect the relevant code and tests together before
editing. Prefer `rg`/`rg --files` to locate command handlers, plugin manifests,
schema objects, completion providers, and existing tests for the same behavior.

## Project Model

Bywaf is an event and evidence orchestration framework, not only a plugin
runner. Plugins should use framework-mediated APIs for events, artifacts,
process execution, secrets, rendering, runtime state, and control-plane
actions.

Normalized events are the shared data model. Raw external tool output should
remain provenance-rich artifact evidence, while normalized events summarize
facts that other commands and plugins can reuse.

Plugin manifests are a review and trust contract. `plugin_check` validates
conformance and provides author feedback; it is not a hostile-code sandbox.
Sandboxing, signing, policy enforcement, encrypted storage, and dependency
security are separate layers.

## Operating Conventions

- Treat uncommitted work as intentional. Read relevant diffs and continue from
  them. Do not revert or overwrite unrelated local edits.
- Prefer small, testable batches. Complete each batch through implementation,
  focused validation, metrics when relevant, and documentation/tracker updates
  when behavior or conventions change.
- End-of-batch reports should include the next suggested plan of action. When
  the likely next step has material choices or questions, include the
  assistant's suggested answers/defaults so the user can quickly approve,
  adjust, or reject them.
- Use existing package boundaries and helper APIs before adding abstractions.
  Split only when the new module has a clear responsibility and reduces future
  friction.
- Keep cross-plugin communication through framework-normalized events,
  artifacts, schemas, and stores. Do not add direct imports between plugins.
- Use framework-mediated services for events, artifacts, processes, secrets,
  rendering, runtime state, and control-plane actions.
- Distinguish conformance checks, trust/signing, policy enforcement,
  encryption-at-rest, and hostile-code sandboxing. A passing checker result is
  not a sandbox.
- Private handoff, tracker, and lessons-learned material may live outside this
  repository. Do not commit local absolute paths to those files; refer to them
  with generic names or repo-relative context only.

## File Size And Architecture

- Use architecture metrics as normal development feedback after larger changes,
  refactors, plugin-surface work, and checker/policy/security-adjacent work:

  ```bash
  python3 scripts/architecture_metrics.py --top 12
  ```

- Treat ordinary source and test files at or above 500 lines as a trigger for
  deduplication and refactoring review when a clean, cohesive split exists.
  This is a refactoring signal, not a hard failure threshold. Larger cohesive
  files are acceptable when splitting would reduce clarity or create
  artificial boundaries.
- As a mandatory post-coding, pre-commit review gate, check any changed
  ordinary source or test file that is at or above 500 lines. Split it before
  committing unless it is cohesive enough that splitting would reduce clarity.
  This keeps file sizes controlled during development and forces the harder
  design choices about responsibility and placement while the context is
  fresh. If a file remains above the threshold, record why it is still cohesive
  and where any follow-up belongs.
- When a split is worthwhile, aim resulting ordinary files at roughly 300-400
  lines rather than merely just under 500. For test files, prefer splitting by
  behavior, command surface, or subsystem boundary. Avoid splitting only to
  satisfy the number when shared setup or scenario flow reads better together.
- Avoid dependency cycles. Do not introduce imports that turn narrow helpers
  into package hubs or create circular dependencies.

## CLI And Output Style

- Use `name=value` for ordinary Bywaf commandlet options that carry values,
  such as `timeout=5`, `host=192.0.2.10`, `sort=host`, and
  `binary=traceroute`.
- Use `--flag` for true boolean/toggle behavior and shell-standard control,
  such as `--help`, `--json`, `--force`, and `--follow`.
- CLI errors should be actionable. Include the expected command shape or point
  to the relevant help command.
- View and inventory commands should inspect state without mutating it.
  Maintenance actions should be explicit.
- Prefer established output shapes for command lines, headings, tables,
  findings, runtime IDs, and inspect-next hints.
- Use `inspect further with:` for follow-up commands instead of vague labels.

## Plugin Authoring And Checker Work

- Plugin manifests are a trust and review contract. `plugin_check` validates
  conformance and gives author feedback; it does not safely execute hostile
  plugin code.
- Generated or submitted plugins are evaluation artifacts. Do not repair them
  silently by hand. Improve docs, skeletons, packets, and checker feedback so
  the generating LLM or author can correct the plugin.
- For process-wrapped plugins, attach raw stdout/stderr/tool output as artifact
  evidence when meaningful, even when normalized events are also emitted.
- Raw external tool output should remain provenance-rich artifact evidence.
  Normalized events should summarize reusable facts.
- Artifact previews must be read-only. Binary previews should render as safe
  non-executing representations such as hex.
- Plugin variables should be exposed to plugin code as a simple config snapshot
  for each invocation. Long-running control state should not depend on live
  mutation of ordinary plugin vars.

## Validation Guidance

Start with focused checks for the surface touched, then broaden when the change
affects shared behavior, security, packaging, or release flow.

Run these checks when the relevant tools are available on the target system. If
`pytest`, `pyright`, `ruff`, `pip-audit`, package builders, or external service
tools are unavailable, say exactly which checks could not be run and do not
treat them as passed.

- Narrow Python behavior: `PYTHONPATH=. pytest -q <focused tests>`
- Plugin checker, manifests, capabilities, skeletons:
  `PYTHONPATH=. pytest -q tests/plugin_check tests/plugin` and relevant
  `python3 scripts/plugin_check.py <plugin-dir-or-zip> --strict-inference`
- Parser, completion, REPL, app dispatch:
  `PYTHONPATH=. pytest -q tests/app_dispatch tests/registry_completion tests/test_completion_regression.py`
- Events, storage, jobs, runtime state:
  `PYTHONPATH=. pytest -q tests/test_events_db.py tests/test_store_protocols.py tests/storage_runner`
- Findings and reports:
  `PYTHONPATH=. pytest -q tests/test_report.py tests/finding`
- Shared architecture or large refactor: focused tests plus
  `PYTHONPATH=. pytest -q tests/test_architecture_metrics.py` and
  `python3 scripts/architecture_metrics.py --top 12`
- Security, plugin loading, secrets, process wrappers, dependency changes:
  focused tests plus `pyright`, `ruff check .`, relevant `plugin_check`, and
  `pip-audit` when dependencies changed or before release-style work.
- Release candidate or broad shared change: `PYTHONPATH=. pytest -q`,
  `pyright`, `ruff check .`, `pip-audit`, architecture metrics, and release
  package build/smoke checks as applicable.

For docs-only changes, inspect the changed docs for broken references and
audience fit. For larger docs changes, run
`python3 scripts/architecture_metrics.py --doc-impact <changed-doc>` when that
script is available and relevant.
