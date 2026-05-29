# Testing

Use this page as the project-level testing map. Plugin-specific testing details
live in [Plugin Testing And Guidelines](plugin_author/testing-and-guidelines.md);
this page explains how those checks fit with framework, package, metrics, and
manual validation.

## Contents

- [Quick Checks](#quick-checks)
- [Choosing The Right Layer](#choosing-the-right-layer)
- [Plugin Testing](#plugin-testing)
- [Framework Testing](#framework-testing)
- [Package Tests](#package-tests)
- [Manual Validation](#manual-validation)
- [Environment Notes](#environment-notes)
- [Release Notes And Importance](#release-notes-and-importance)
- [Pre-Commit Checklist](#pre-commit-checklist)

## Quick Checks

Run the full Python test suite when practical:

```bash
PYTHONPATH=. pytest -q
```

Use focused checks while editing a specific area:

```bash
PYTHONPATH=. pytest -q tests/test_plugin_check.py
PYTHONPATH=. pytest -q tests/test_registry_completion.py tests/test_completion_regression.py
PYTHONPATH=. pytest -q tests/test_events_db.py tests/test_storage_runner_plugins.py
PYTHONPATH=. pytest -q tests/test_report.py tests/test_finding_grouping.py
```

Run Ruff on changed Python paths:

```bash
ruff check bywaf tests scripts
```

CI runs architecture metrics on every push and pull request. Use the same
metrics locally before and after larger refactors:

```bash
python scripts/architecture_metrics.py --top 12
python scripts/architecture_metrics.py --top 12 --churn
python scripts/architecture_metrics.py --doc-impact docs/REPORTING.md
```

The metrics report includes both Python code pressure and documentation
pressure. Documentation metrics are cohesion/coupling hints: they flag oversized
pages, heavily linked pages, stale terms, repeated headings, audience mixing,
and likely related pages to inspect after a documentation change.

## Choosing The Right Layer

Start at the narrowest layer that can catch the bug:

- Plugin protocol logic: test `detect.py` or equivalent pure functions without
  Bywaf imports.
- Finding mapping: test that `findings.py` emits normalized payloads, subjects,
  target scopes, identifiers, and group keys.
- Plugin schema: run `scripts/plugin_check.py` or
  `python -m bywaf.tools.plugin_check` against plugin directories and skeletons.
- Commandlet integration: load through `PluginRegistry` and execute with the
  runner or app dispatch path.
- REPL behavior: test parser, completion, script loading, expansion previews,
  and display rendering.
- Runtime persistence: test `EventStore`, jobs, steps, pipelines, artifacts,
  secrets, and variables.
- Reporting: test grouping, scoped selectors, review-state events, detail
  rendering, and accepted/deferred/rejected filtering.
- Packaging: build and smoke-test `.deb` and `.rpm` artifacts.
- Manual network behavior: use controlled targets only; do not put live network
  dependence in normal CI tests.

## Plugin Testing

Detailed plugin guidance lives in
[Plugin Testing And Guidelines](plugin_author/testing-and-guidelines.md). For
most plugins, use this progression:

1. Test protocol parsing and detection functions without Bywaf.
2. Test finding payloads and event payloads as plain dictionaries.
3. Run `plugin_check` to verify manifest, decorator placement, capabilities,
   cancellability, finding helpers, and JSON-serializable yields.
4. Add an integration test that runs the commandlet through the framework path.
5. Keep live network tests as manual tests or explicitly skipped tests unless
   the target is local and deterministic.

Useful plugin-focused commands:

```bash
PYTHONPATH=. pytest -q tests/test_plugin_check.py
PYTHONPATH=. pytest -q tests/test_repo_exposure.py
python scripts/plugin_check.py docs/plugin_skeletons/native_vulnerability
```

## Framework Testing

Use these suites as starting points for common framework changes:

- App dispatch, command parsing, and REPL flows:
  `tests/test_app_dispatch.py`, `tests/test_user_flows.py`.
- Completion:
  `tests/test_registry_completion.py`, `tests/test_completion_regression.py`,
  `tests/test_interactive_completion_smoke.py`.
- Runtime, DB, jobs, steps, and events:
  `tests/test_events_db.py`, `tests/test_store_protocols.py`,
  `tests/test_storage_runner_plugins.py`,
  `tests/test_resources_history_config.py`.
- Findings and reports:
  `tests/test_finding_grouping.py`, `tests/test_finding_report.py`,
  `tests/test_finding_dedupe.py`, `tests/test_report.py`.
- Secrets, keys, and bundles:
  `tests/test_secrets.py`, `tests/test_keyring.py`, `tests/test_bundle.py`.
- Built-in plugins:
  `tests/test_nmap_backend.py`, `tests/test_repo_exposure.py`,
  `tests/test_framework_http_app.py`.
- Architecture metrics:
  `tests/test_architecture_metrics.py`.

When a change touches cross-cutting runtime behavior, run at least the affected
focused suite plus one runner/storage suite. For parser or REPL changes, include
completion and app-dispatch tests.

## Package Tests

Build packages after install-path, dependency, entry point, or release metadata
changes:

```bash
scripts/build_release_packages.sh
```

Smoke-test release packages where practical:

```bash
tests/scripts/smoke_rpm_package.sh
```

The install guide lists OS dependency blocks and optional plugin dependencies:
[Install Guide](../INSTALL.md).

## Manual Validation

Manual tests should exercise the operator workflow, not just isolated commands.
Good manual passes include:

- Port discovery with a fresh DB against an authorized target. For local
  testing, start `scripts/fake_telnet_service.py` and scan
  `network/portscanner host=127.0.0.1 port=2323 arguments="-Pn -sT -sV"`.
  Host values may be single hosts, DNS names, CIDR ranges, dash ranges, or
  comma/space-separated lists; port values may be comma-separated ports and
  ranges, such as `22,80,443` or `1-60,80-90`.
- Runtime scoping:
  `ports`, `ports sort=port`, `event port.open host=<ip>`,
  `jobs host=<ip>`, `steps host=<ip>`, `pipelines host=<ip>`.
- Telnet finding path with a controlled local service:
  `scripts/fake_telnet_service.py`, then scan `127.0.0.1:2323`.
- Repository exposure finding path with a controlled HTTP server exposing
  `/.git/config`.
- Reporting and review:
  `report`, `report status=all`,
  `report accept all note="confirmed in manual pass"`,
  `event finding.reviewed`.
- Script behavior:
  `script load file=scripts/manual_finding_report_flow.bywaf`.

Use `db new` before manual sessions when old events would make results hard to
read. Do not bake third-party targets into committed scripts; use local
fixtures or systems you own or are explicitly authorized to test.

## Environment Notes

Use a virtual environment for local development:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

On Debian and Ubuntu systems, install the venv package first if `ensurepip` is
missing:

```bash
sudo apt install python3-venv
```

Some plugins need optional system tools or Python libraries. For example, the
Nmap-backed scanner needs the `nmap` binary and one supported Python binding
such as `python-libnmap` installed in the active venv.

CI currently checks supported Python runtimes such as Python 3.11 and 3.12.
Local newer interpreters can be useful, but CI failures on supported runtimes
take priority.

## Release Notes And Importance

When discussing completed work, classify each notable item by practical
importance before it goes into the changelog:

- `high`: changes that materially affect operator workflow, data model,
  compatibility, security posture, or plugin author schemas.
- `medium`: visible behavior, documentation structure, packaging, or developer
  workflow changes that users should notice but that do not redefine a core
  contract.
- `low`: polish, clarification, small maintenance, and internal cleanup that is
  worth recording but unlikely to change how users work.

Changelog bullets should carry the agreed label (`[high]`, `[medium]`, or
`[low]`) and additions/changes should be ordered from high to low. The label is
a release-triage signal, not a substitute for explaining the change clearly.

## Pre-Commit Checklist

Before committing non-trivial changes:

1. Run Ruff on changed Python files.
2. Run focused tests for the touched subsystem.
3. Run `plugin_check` when plugin skeletons, plugin manifests, finding helpers,
   or commandlet decorators change.
4. Run architecture metrics when splitting files or reducing coupling.
5. Update docs when command syntax, user workflow, plugin schemas, or release
   packaging changes.
