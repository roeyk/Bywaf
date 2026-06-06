# Bywaf

Bywaf is a Python 3 commandlet framework for authorized web application and
network testing workflows. It gives operators an interactive shell, plugin
commandlets, durable SQLite-backed events, artifacts, notes, runtime metadata,
and report-oriented finding workflows.

Bywaf plugins are **not** Veil modules, Metasploit modules, `info` dictionaries,
or `run/exploit` entrypoint scripts. The current plugin API is commandlet-based:
plugin authors use `@commandlet`, `@argument`, `@option`, `CommandletBase`,
`CommandContext`, a `plugin()` factory, and a `bywaf.plugin.toml` manifest.

The core idea is simple:

```text
hostscanner 192.168.1.0/24 | portscanner | http_probe | webfin | nikto
hostscanner 192.168.1.0/24 | portscanner | tcp_banner
```

Each pipeline step emits normalized events into the project database. Later
steps, reports, artifact searches, audit exports, and future frontends inspect
those recorded facts instead of scraping terminal scrollback.

Evidence handling is a first-class design goal. Artifacts record body size,
SHA-256, content type, and runtime provenance; findings and reports should point
back to those records instead of detached screenshots or copied snippets. Bywaf
is being hardened toward a chain-of-custody workflow where evidence is
immutable, verifiable, and reviewable from the same event ledger that drove the
assessment.

Use Bywaf only on systems and networks where you have explicit authorization.

## Contents

- [Why Bywaf](#why-bywaf)
- [Install And Run](#install-and-run)
- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [Plugins](#plugins)
- [Documentation](#documentation)
- [Development](#development)

## Why Bywaf

Typical assessment workflows often involve running a tool, copying output,
transforming it, saving notes somewhere else, running another tool, and later
trying to reconstruct what happened. Bywaf is designed to keep that provenance
inside the workflow.

| Tool | Good at | Bywaf's distinction |
| --- | --- | --- |
| Bash | Fast shell glue | Durable event flow, runtime records, notes, artifacts, and provenance are built in. |
| Metasploit | Exploitation workflows and module ecosystem | Bywaf focuses on auditable event-driven orchestration over normalized assessment data. |
| Airflow | Scheduled data pipeline | Bywaf is interactive, operator-driven, and built around live security assessment workflows. |
| Python scripts | Maximum flexibility | Bywaf gives scripts a common shell, plugin API, event store, audit trail, and reusable workflow state. |

## Install And Run

For OS-specific dependency blocks and package-build prerequisites, see
[INSTALL.md](INSTALL.md).

During development, run Bywaf from the repository root:

```bash
python3 -m bywaf --help
python3 -m bywaf
```

For an editable local install:

```bash
python3 -m pip install -e .
bywaf --help
bywaf
```

For a local pip package build:

```bash
scripts/build_pip_package.sh
python3 -m pip install dist/bywaf-0.12.2-py3-none-any.whl
bywaf --help
```

Optional external tools used by bundled wrapper commandlets include `nmap`,
`nikto`, `eyewitness`/`screenshotter`, and `kismet`.

## Quick Start

For a fuller first-ten-minutes operator path, see
[docs/OPERATOR_QUICKSTART.md](docs/OPERATOR_QUICKSTART.md).

Create durable user configuration and a default project:

```bash
bywaf --setup
```

Start the Bywaf interpreter:

```bash
bywaf
```

Run a small local pipeline:

```text
bywaf> hostscanner 127.0.0.1 | portscanner
```

Inspect runtime state and events:

```text
bywaf> job
bywaf> pipeline
bywaf> step
bywaf> job host=192.0.2.10
bywaf> pipeline host=192.0.2.10
bywaf> step host=192.0.2.10
bywaf> event host.found
bywaf> event step=1
```

Load a local plugin during development:

```text
bywaf> plugin load=./plugins/myplugin --force
```

Set plugin variables:

```text
bywaf> set network/portscanner.port=22,80,443
bywaf> portscanner host=127.0.0.1
```

View finding-oriented output:

```text
bywaf> report
bywaf> report pipeline=1
```

View normalized inventory without remembering the producer tool:

```text
bywaf> hosts --last
bywaf> services --new
bywaf> web
bywaf> wafs
bywaf> shares
bywaf> routes
bywaf> certs
bywaf> banners
bywaf> paths
bywaf> screenshots
bywaf> schemas topic=web.
```

## Core Concepts

- **Commandlet**: a small command provided by a plugin or the framework.
- **Pipeline**: one command expression or attached workflow made of one or more
  pipeline step.
- **Pipeline step**: one commandlet invocation inside a pipeline. Select it
  with `step=...`.
- **Job**: the supervised foreground or background execution lifecycle that runs
  one or more step.
- **Event**: a durable topic/payload record emitted by commandlets or framework
  services.
- **Artifact**: an evidence file stored in the paired artifact database and
  linked to step, pipeline, or job provenance.
- **Finding**: a normalized candidate or confirmed security issue, usually
  derived from lower-level fact events.

See [docs/TERMINOLOGY.md](docs/TERMINOLOGY.md) for precise definitions.

## Plugins

Bundled plugins live under [bywaf/plugins](bywaf/plugins). Larger plugins use a
directory layout such as:

```text
bywaf/plugins/http/repo_exposure/
  plugin.py
  command.py
  detect.py
  findings.py
  models.py
  bywaf.plugin.toml
```

The plugin authoring guide starts at
[docs/plugin_author/README.md](docs/plugin_author/README.md). Skeletons for
native, library-backed, process-wrapped, and vulnerability-detection plugins
are in [docs/plugin_skeletons](docs/plugin_skeletons).

Current plugin API at a glance:

```text
plugin.py          decorated CommandletBase class plus plugin() factory
command.py         runtime parsing, event iteration, context interaction
detect.py          pure detection/protocol logic, testable without Bywaf
findings.py        normalized finding payloads via bywaf.finding helpers
models.py          plugin-local domain objects
bywaf.plugin.toml  sidecar manifest contract, including [plugin].version, capabilities, and traits
```

Before loading or sharing a plugin, run the checker:

```bash
python3 scripts/plugin_check.py path/to/plugin_dir
python3 scripts/plugin_check.py path/to/plugin.zip --temp-checkout --strict-inference --llm-feedback
python3 scripts/plugin_check.py --all
```

## Documentation

- [docs/DOCUMENTATION_PATHS.md](docs/DOCUMENTATION_PATHS.md): role-based
  reading sequences for users, operators, plugin developers, framework
  developers, security reviewers, packagers, and documentation maintainers.
- [USAGE.md](USAGE.md): full user manual and command examples.
- [docs/README.md](docs/README.md): documentation index.
- [docs/FAQ.md](docs/FAQ.md): common tasks and recipes.
- [docs/TERMINOLOGY.md](docs/TERMINOLOGY.md): canonical terms.
- [docs/RUNTIME_MODEL.md](docs/RUNTIME_MODEL.md): job, pipeline, step, signals, and snapshots.
- [docs/EVENT_MODEL.md](docs/EVENT_MODEL.md): event topics, provenance, replay, and framework requests.
- [docs/FINDING_MODEL.md](docs/FINDING_MODEL.md): normalized finding payloads, grouping, and reporting.
- [docs/REPORTING.md](docs/REPORTING.md): `report` usage, grouping, and review state.
- [docs/SAVE_EXPORT_MODEL.md](docs/SAVE_EXPORT_MODEL.md): load/save/export/archive semantics.
- [docs/RETENTION_AND_COMPACTION.md](docs/RETENTION_AND_COMPACTION.md): evidence retention and compaction policy.
- [docs/MANIFEST_SPECIFICATION.md](docs/MANIFEST_SPECIFICATION.md): plugin sidecar TOML schema.
- [docs/BUNDLED_PLUGIN_MANUAL.md](docs/BUNDLED_PLUGIN_MANUAL.md): bundled plugin families, examples, outputs, findings, and artifacts.
- [docs/FRAMEWORK_SURFACE.md](docs/FRAMEWORK_SURFACE.md): capabilities, topics, and bundled commandlets.
- [docs/TESTING.md](docs/TESTING.md): plugin, framework, package, metrics, and manual testing map.
- [docs/plugin_author/README.md](docs/plugin_author/README.md): plugin developer guide.
- [docs/FRAMEWORK_DEVELOPMENT.md](docs/FRAMEWORK_DEVELOPMENT.md): core framework contributor guide.
- [docs/DEVELOPMENT_WORKFLOW_README.md](docs/DEVELOPMENT_WORKFLOW_README.md): maintainer human-plus-LLM workflow and private tracker/handoff boundaries.

## Development

For plugin work, start with [docs/plugin_author/README.md](docs/plugin_author/README.md)
and the skeletons in [docs/plugin_skeletons/](docs/plugin_skeletons/). For core
framework work, start with
[docs/FRAMEWORK_DEVELOPMENT.md](docs/FRAMEWORK_DEVELOPMENT.md), then use
[docs/ARCHITECTURE_METRICS.md](docs/ARCHITECTURE_METRICS.md) to pick and check
refactor targets. For test selection, package smoke checks, and manual
validation flows, see [docs/TESTING.md](docs/TESTING.md).
For the maintainer collaboration model used with LLM coding agents, see
[docs/DEVELOPMENT_WORKFLOW_README.md](docs/DEVELOPMENT_WORKFLOW_README.md).

Bywaf is intentionally friendly to LLM-assisted development, but the guardrails
live in the framework rather than in assistant trust. Plugin skeletons use
small, explicit files; manifests are data-only contracts; event schemas,
capabilities, variables, and emitted topics are inspectable before plugin code
runs; and `plugin_check` provides machine-readable feedback that can be pasted
back into an assistant. For core framework work, the development docs, tracker
conventions, architecture metrics, and focused test map make it easier for an
assistant or human maintainer to make narrow, reviewable changes instead of
large speculative rewrites.

Run the focused test suite while working:

```bash
PYTHONPATH=. pytest -q
```

Useful checks:

```bash
PYTHONPATH=. pytest -q tests/test_plugin_check.py
PYTHONPATH=. pytest -q tests/test_registry_completion.py
PYTHONPATH=. pytest -q tests/test_storage_runner_plugins.py
python3 scripts/bundled_plugin_manual_check.py
```

Build release packages locally:

```bash
scripts/build_release_packages.sh
```

Project changes are summarized in [CHANGELOG.md](CHANGELOG.md), and pending work
is tracked in [docs/TODO.md](docs/TODO.md).
