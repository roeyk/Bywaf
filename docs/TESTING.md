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
PYTHONPATH=. pytest -q tests/registry_completion tests/test_completion_regression.py
PYTHONPATH=. pytest -q tests/test_events_db.py tests/storage_runner
PYTHONPATH=. pytest -q tests/test_report.py tests/finding
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
python scripts/bundled_plugin_manual_check.py
```

The metrics report includes both Python code pressure and documentation
pressure. Documentation metrics are cohesion/coupling hints: they flag oversized
pages, heavily linked pages, stale terms, repeated headings, audience mixing,
and likely related pages to inspect after a documentation change.

The bundled plugin manual drift check compares bundled plugin manifests with
`docs/BUNDLED_PLUGIN_MANUAL.md`. It catches stale plugin lists, family counts,
commandlet counts, and commandlet headings after bundled plugin changes.

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
  rendering, and accepted/confirmed/deferred/rejected filtering.
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
  `tests/app_dispatch/`, `tests/test_user_flows.py`.
- Completion:
  `tests/registry_completion/`, `tests/test_completion_regression.py`,
  `tests/test_interactive_completion_smoke.py`.
- Runtime, DB, jobs, steps, and events:
  `tests/test_events_db.py`, `tests/test_store_protocols.py`,
  `tests/storage_runner/`,
  `tests/test_resources_history_config.py`.
- Findings and reports:
  `tests/finding/`, `tests/test_report.py`.
- Secrets, keys, and bundles:
  `tests/test_secrets.py`, `tests/test_keyring.py`, `tests/test_bundle.py`.
- Built-in plugins:
  `tests/test_nmap_backend.py`, `tests/test_repo_exposure.py`,
  `tests/framework_http_app/`.
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
tests/scripts/smoke_pip_package.sh
tests/scripts/smoke_deb_package.sh
tests/scripts/smoke_rpm_package.sh
```

Use this package matrix before tagging a release or after changing packaging,
entry points, install paths, package data, bundled manifests, release metadata,
or package dependencies:

| Artifact | Local validation | What it verifies | Required local tools |
| --- | --- | --- | --- |
| Source and wheel | `tests/scripts/smoke_pip_package.sh` | Builds sdist/wheel, installs into a temporary venv, runs installed-user smoke, and checks bundled plugin config loading. | Python build tooling and venv support. |
| Debian package | `tests/scripts/smoke_deb_package.sh` | Builds or finds the `.deb`, verifies package metadata, installs it with apt, runs `/usr/bin/bywaf` through installed-user smoke, and removes the package on exit. | `dpkg-deb`, `sudo`, Debian package build tools. |
| RPM package | `tests/scripts/smoke_rpm_package.sh` | Builds source and binary RPMs, extracts the RPM payload, verifies the extracted command and package tree, and runs installed-user smoke against the extracted install root. | `rpmbuild`, `rpm2cpio`, `cpio`, Python build tooling. |

The GitHub `Release packages` workflow is the release gate for the full package
matrix. It runs on `v*` tags and can also be run manually with:

```bash
gh workflow run "Release packages" --ref main
```

Before closing a package-matrix issue or tagging a release, confirm that the
workflow reaches `success` and uploads `bywaf-release-artifacts`. Normal push CI
does not run the release package workflow, so a green push alone does not prove
the wheel, Debian, and RPM package matrix.

Version alignment is covered by `tests/test_packaging_install_paths.py`: the
Python package version, `bywaf.__version__`, Debian changelog, RPM spec, and
README wheel example must agree before release packaging.

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
  `finding confirm 1 note="confirmed in manual pass"`,
  `event finding.reviewed`.
- Script behavior:
  `script load file=scripts/manual_finding_report_flow.bywaf`.

Use `db new` before manual sessions when old events would make results hard to
read. In ad hoc mode, that fresh database remains the active local database for
later plain `bywaf` startups; pass `--database path/to/db.sqlite3` when a test
or reproduction needs a specific database instead. Do not bake third-party
targets into committed scripts; use local fixtures or systems you own or are
explicitly authorized to test.

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
