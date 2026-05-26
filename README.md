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
```

Each pipeline step emits normalized events into the project database. Later
steps, reports, artifact searches, audit exports, and future frontends inspect
those recorded facts instead of scraping terminal scrollback.

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
| Airflow | Scheduled data pipelines | Bywaf is interactive, operator-driven, and built around live security assessment workflows. |
| Python scripts | Maximum flexibility | Bywaf gives scripts a common shell, plugin API, event store, audit trail, and reusable workflow state. |

## Install And Run

During development, run Bywaf from the repository root:

```bash
python3 -m bywaf --help
python3 -m bywaf repl
```

For an editable local install:

```bash
python3 -m pip install -e .
bywaf --help
bywaf repl
```

For a local pip package build:

```bash
scripts/build_pip_package.sh
python3 -m pip install dist/bywaf-0.12.0-py3-none-any.whl
bywaf --help
```

Optional external tools used by bundled wrapper commandlets include `nmap`,
`nikto`, `eyewitness`, and `kismet`.

## Quick Start

Start the REPL:

```bash
bywaf repl
```

Run a small local pipeline:

```text
bywaf> hostscanner 127.0.0.1 | portscanner
```

Inspect runtime state and events:

```text
bywaf> jobs
bywaf> pipelines
bywaf> steps
bywaf> jobs host=192.0.2.10
bywaf> pipelines host=192.0.2.10
bywaf> steps host=192.0.2.10
bywaf> event host.found
bywaf> event step=1
```

Load a local plugin during development:

```text
bywaf> plugin load=./plugins/myplugin --force
```

Set plugin variables:

```text
bywaf> set network/portscanner.ports=22,80,443
bywaf> portscanner 127.0.0.1
```

View finding-oriented output:

```text
bywaf> report
bywaf> report pipeline=1
```

## Core Concepts

- **Commandlet**: a small command provided by a plugin or the framework.
- **Pipeline**: one command expression or attached workflow made of one or more
  pipeline steps.
- **Pipeline step**: one commandlet invocation inside a pipeline. Select it
  with `step=...`.
- **Job**: the supervised foreground or background execution lifecycle that runs
  one or more steps.
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
bywaf.plugin.toml  sidecar manifest contract for capabilities and traits
```

Before loading or sharing a plugin, run the checker:

```bash
python3 scripts/plugin_check.py path/to/plugin_dir
```

## Documentation

- [USAGE.md](USAGE.md): full user manual and command examples.
- [docs/README.md](docs/README.md): documentation index.
- [docs/FAQ.md](docs/FAQ.md): common tasks and recipes.
- [docs/TERMINOLOGY.md](docs/TERMINOLOGY.md): canonical terms.
- [docs/RUNTIME_MODEL.md](docs/RUNTIME_MODEL.md): jobs, pipelines, steps, signals, and snapshots.
- [docs/EVENT_MODEL.md](docs/EVENT_MODEL.md): event topics, provenance, replay, and framework requests.
- [docs/FINDING_MODEL.md](docs/FINDING_MODEL.md): normalized finding payloads, grouping, and reporting.
- [docs/REPORTING.md](docs/REPORTING.md): `report` usage, grouping, and review state.
- [docs/SAVE_EXPORT_MODEL.md](docs/SAVE_EXPORT_MODEL.md): load/save/export/archive semantics.
- [docs/MANIFEST_SPECIFICATION.md](docs/MANIFEST_SPECIFICATION.md): plugin sidecar TOML schema.
- [docs/FRAMEWORK_SURFACE.md](docs/FRAMEWORK_SURFACE.md): capabilities, topics, and bundled commandlets.

## Development

Run the focused test suite while working:

```bash
PYTHONPATH=. pytest -q
```

Useful checks:

```bash
PYTHONPATH=. pytest -q tests/test_plugin_check.py
PYTHONPATH=. pytest -q tests/test_registry_completion.py
PYTHONPATH=. pytest -q tests/test_storage_runner_plugins.py
```

Build release packages locally:

```bash
scripts/build_release_packages.sh
```

Project changes are summarized in [CHANGELOG.md](CHANGELOG.md), and pending work
is tracked in [docs/TODO.md](docs/TODO.md).
