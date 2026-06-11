# Tools

Bywaf ships human-facing tools under `scripts/` and implementation helpers
under `bywaf/tools/`. The `scripts/` commands are the normal interface for
plugin authors, framework developers, release maintainers, and documentation
maintainers. The `bywaf/tools/` modules are reusable implementation code used
by those scripts and by tests.

**Audience**

This document is for plugin authors, framework developers, release maintainers,
documentation maintainers, performance investigators, and LLM-assisted
contributors who need to know which tool to run, who normally uses it, what
process it belongs to, and what arguments it accepts.

**Related Documents**

- [Testing](TESTING.md): how tools fit into validation.
- [Plugin Packaging And Checking](plugin_author/packaging-and-checking.md):
  plugin checker workflow.
- [Plugin Author Workflow](plugin_author/workflow.md): create/check/test/load
  loop for plugin work.
- [Architecture Metrics](ARCHITECTURE_METRICS.md): metric interpretation.
- [Performance](PERFORMANCE.md): benchmark usage and optimization workflow.
- [Framework Development](FRAMEWORK_DEVELOPMENT.md): maintainer change paths.

## Contents

- [Running Tools](#running-tools)
- [Tool Index](#tool-index)
- [plugin_new.py](#plugin_newpy)
- [plugin_check.py](#plugin_checkpy)
- [plugin_graph.py](#plugin_graphpy)
- [plugin_manifest_sign.py](#plugin_manifest_signpy)
- [plugin_catalog.py](#plugin_catalogpy)
- [bundled_plugin_manual_check.py](#bundled_plugin_manual_checkpy)
- [architecture_metrics.py](#architecture_metricspy)
- [sqlite_contention_benchmark.py](#sqlite_contention_benchmarkpy)
- [sqlite_query_benchmark.py](#sqlite_query_benchmarkpy)
- [Package Build Scripts](#package-build-scripts)
- [Manual Test Helpers](#manual-test-helpers)
- [Internal Modules](#internal-modules)
- [Adding A New Tool](#adding-a-new-tool)

## Running Tools

Run tools from the repository root. Python tools usually expect the checkout on
`PYTHONPATH`:

```bash
PYTHONPATH=. python3 scripts/plugin_check.py path/to/plugin --strict-inference
PYTHONPATH=. python3 scripts/architecture_metrics.py
```

Some implementation modules under `bywaf/tools/` can also be invoked with
`python -m`, but the documented `scripts/` wrappers are the preferred stable
interface.

## Tool Index

| Tool | Main Audience | Process |
| --- | --- | --- |
| `scripts/plugin_new.py` | Plugin authors, LLM-assisted plugin authors | Plugin scaffolding |
| `scripts/plugin_check.py` | Plugin authors, reviewers, maintainers | Plugin validation and submission review |
| `scripts/plugin_graph.py` | Plugin authors, framework developers | Manifest relationship inspection |
| `scripts/plugin_manifest_sign.py` | Plugin publishers, release maintainers | Manifest signing |
| `scripts/plugin_catalog.py` | Release and catalog maintainers | Plugin catalog build/sign/verify |
| `scripts/bundled_plugin_manual_check.py` | Maintainers, documentation maintainers | Bundled plugin manual drift checks |
| `scripts/architecture_metrics.py` | Framework developers, documentation maintainers | Refactor and documentation metrics |
| `scripts/sqlite_contention_benchmark.py` | Performance investigators | SQLite write-contention measurement |
| `scripts/sqlite_query_benchmark.py` | Performance investigators | SQLite query-latency measurement |
| `scripts/build_*_package.sh` | Release maintainers | Release package builds |
| `scripts/fake_telnet_service.py` | Maintainers, plugin developers | Controlled manual network fixture |
| `scripts/manual_portscanner_flow.py` | Maintainers, plugin developers | Controlled manual portscanner flow |

## plugin_new.py

**What it does:** Generates a minimal native plugin scaffold. It can create an
external filesystem plugin or a bundled-native plugin under `bywaf/plugins/`.

**Who uses it:** Plugin authors, maintainers creating small bundled plugins,
and LLM-assisted plugin authors.

**Process:** Use at the start of plugin development to create the file layout,
manifest, minimal commandlet, test placeholder, and generated metadata. Replace
the scaffold behavior with real protocol/detection logic, then run
`plugin_check.py`.

**Common usage:**

```bash
python3 scripts/plugin_new.py http_title --output /tmp/http_title --topic http.title
python3 scripts/plugin_new.py http_methods --bundled http --topic http.methods
```

**Arguments:**

| Argument | Meaning |
| --- | --- |
| `name` | Required lowercase snake_case plugin name. |
| `--output PATH` | Plugin directory to create. Defaults to `./NAME` or the bundled family path. |
| `--bundled FAMILY` | Generate a bundled-native package under `bywaf/plugins/FAMILY/NAME`. |
| `--commandlet NAME` | Commandlet name. Defaults to `name`. |
| `--argument NAME` | Single positional argument name. Defaults to `target`. |
| `--topic TOPIC` | Emitted event topic. Defaults to `COMMANDLET.observed`. |
| `--description TEXT` | Commandlet description. |
| `--plugin-version VERSION` | Manifest plugin version. Defaults to `0.1.0`. |

## plugin_check.py

**What it does:** Validates plugin manifests and source metadata. It checks
manifest shape, commandlet metadata, capabilities, emitted topics, parser
contracts, signature policy, zip submissions, and optional relationship graph
context.

**Who uses it:** Plugin authors, plugin reviewers, maintainers, CI, and
LLM-assisted workflows.

**Process:** Run before loading, sharing, packaging, or accepting a plugin.
Use strict and LLM modes when reviewing generated plugins.

**Common usage:**

```bash
python3 scripts/plugin_check.py path/to/plugin --strict-inference
python3 scripts/plugin_check.py path/to/plugin.zip --temp-checkout --strict-inference --llm-feedback
python3 scripts/plugin_check.py --all --strict-inference
python3 scripts/plugin_check.py path/to/plugin --graph
```

**Arguments:**

| Argument | Meaning |
| --- | --- |
| `plugin` | Filesystem plugin directory or `.zip` containing `plugin.py` and `bywaf.plugin.toml`. Optional when `--all` is used. |
| `--all` | Validate every bundled plugin listed in `bywaf.plugins/plugins.toml`. |
| `--manifest-key PATH` | Trusted public key used to verify `bywaf.plugin.toml`. |
| `--verify` | Require a verified manifest signature. |
| `--temp-checkout` | Copy the Bywaf tree to a temporary checkout, apply a plugin submission, and validate there. Useful for zip submissions. |
| `--strict-inference` | Fail when static inference finds capabilities missing from command specs. |
| `--json` | Emit machine-readable JSON. |
| `--llm-feedback` | Emit concise feedback suitable for pasting into an LLM chat. |
| `--graph` | Include manifest relationship graph context. |

## plugin_graph.py

**What it does:** Inspects bundled plugin manifest relationships without
importing plugin code.

**Who uses it:** Framework developers, plugin authors working with topics, and
reviewers checking provider/consumer relationships.

**Process:** Use during manifest dependency work, topic/schema review, and
plugin graph debugging.

**Common usage:**

```bash
python3 scripts/plugin_graph.py
python3 scripts/plugin_graph.py --topic port.open
python3 scripts/plugin_graph.py --provider http.probe
python3 scripts/plugin_graph.py --json
```

**Arguments:**

| Argument | Meaning |
| --- | --- |
| `--provider NAME` | Show relationships for one bundled provider entry. |
| `--topic TOPIC` | Show schema providers, producers, and consumers for one topic. |
| `--json` | Emit machine-readable graph data. |

## plugin_manifest_sign.py

**What it does:** Signs a plugin manifest with an Ed25519 private key.

**Who uses it:** Plugin publishers and release maintainers.

**Process:** Use when preparing trusted plugin manifests. This signs only the
canonical `bywaf.plugin.toml` sidecar values, not the plugin source file.
Ordinary local plugin development usually does not require signing.

**Common usage:**

```bash
python3 scripts/plugin_manifest_sign.py --manifest bywaf.plugin.toml --private manifest-signing.key --in-place
```

**Arguments:**

| Argument | Meaning |
| --- | --- |
| `--manifest PATH` | Required `bywaf.plugin.toml` to sign. |
| `--private PATH` | Required Ed25519 private key PEM. |
| `--output PATH` | Write signed manifest to this path. |
| `--in-place` | Append the signature block to the manifest file. |
| `--passphrase-env NAME` | Read the private-key passphrase from an environment variable. |

## plugin_catalog.py

**What it does:** Builds, signs, verifies, and checks plugin catalog metadata.

**Who uses it:** Release maintainers and future plugin catalog maintainers.

**Process:** Use during release/catalog workflows, not during ordinary plugin
implementation. A signed catalog binds reviewed plugin entries to hashes of
both `plugin.py` and `bywaf.plugin.toml`, so catalog verification is the current
package-integrity check for plugin code plus sidecar metadata.

**Common usage:**

```bash
python3 scripts/plugin_catalog.py build --output catalog.json --source bundled
python3 scripts/plugin_catalog.py generate-key --private catalog.key --public catalog.pub
python3 scripts/plugin_catalog.py sign --catalog catalog.json --private catalog.key --signer maintainer --output catalog.signed.json
python3 scripts/plugin_catalog.py verify --catalog catalog.signed.json --public catalog.pub --check-tree
python3 scripts/plugin_catalog.py check --catalog catalog.signed.json
```

**Subcommands And Arguments:**

| Subcommand | Arguments | Meaning |
| --- | --- | --- |
| `build` | `--output/-o PATH`, `--plugin-root PATH`, `--plugin-config PATH`, `--source LABEL` | Build an unsigned catalog from bundled or filesystem plugin metadata. |
| `generate-key` | `--private PATH`, `--public PATH` | Generate an encrypted Ed25519 catalog keypair. |
| `sign` | `--catalog PATH`, `--private PATH`, `--signer NAME`, `--output/-o PATH` | Sign a catalog file. |
| `verify` | `--catalog PATH`, `--public PATH`, `--check-tree` | Verify catalog signature and optionally validate hashes against the checkout. |
| `check` | `--catalog PATH` | Verify catalog hashes against the current checkout. |

## bundled_plugin_manual_check.py

**What it does:** Verifies that `docs/BUNDLED_PLUGIN_MANUAL.md` matches bundled
plugin manifests for family counts, plugin names, commandlet counts, and
commandlet headings.

**Who uses it:** Maintainers, release maintainers, and documentation
maintainers.

**Process:** Run after bundled plugin changes, commandlet renames, manifest
edits, or bundled plugin manual updates.

**Common usage:**

```bash
python3 scripts/bundled_plugin_manual_check.py
```

**Arguments:** None.

## architecture_metrics.py

**What it does:** Reports source-code and documentation pressure metrics:
module size, imports, fan-in/fan-out, hub score, complexity, cycles,
documentation pressure for dense source, security-surface hints, documentation
size, link coupling, stale terms, duplicate headings, and audience-mixing
hints.

**Who uses it:** Framework developers, documentation maintainers,
LLM-assisted contributors, and release reviewers.

**Process:** Run before and after larger refactors, when deciding whether a
module needs splitting, and after documentation restructuring.

**Common usage:**

```bash
python3 scripts/architecture_metrics.py --top 12
python3 scripts/architecture_metrics.py --top 12 --churn
python3 scripts/architecture_metrics.py --doc-impact docs/REPORTING.md
python3 scripts/architecture_metrics.py --json
```

**Arguments:**

| Argument | Meaning |
| --- | --- |
| `root` | Optional Python package directory to inspect. Defaults to `bywaf`. |
| `--package NAME` | Dotted package name. Defaults to the root directory name. |
| `--tests-root PATH` | Test directory used for rough module reference counts. |
| `--docs-root PATH` | Docs directory for Markdown cohesion/coupling metrics. |
| `--doc-impact PATH` | Rank docs related to one changed Markdown file. |
| `--top N` | Rows to show in each section. Defaults to `12`. |
| `--churn` | Include git churn counts from local history. |
| `--json` | Emit JSON instead of text. |

## sqlite_contention_benchmark.py

**What it does:** Measures SQLite event-store write behavior under multiple
writer processes.

**Who uses it:** Framework developers and performance investigators.

**Process:** Run when investigating event-store contention, storage backend
changes, or performance regressions related to concurrent event writes.

**Common usage:**

```bash
PYTHONPATH=. python3 scripts/sqlite_contention_benchmark.py --writers 4 --events-per-writer 1000
PYTHONPATH=. python3 scripts/sqlite_contention_benchmark.py --database /tmp/bywaf-bench.sqlite3 --json
```

**Arguments:**

| Argument | Meaning |
| --- | --- |
| `--database PATH` | Database path. Defaults to a temporary file. |
| `--writers N` | Number of concurrent writer processes. Defaults to `4`. |
| `--events-per-writer N` | Events each writer publishes. Defaults to `1000`. |
| `--payload-bytes N` | Payload bytes in each event. Defaults to `128`. |
| `--read-every N` | Each writer performs one read every `N` writes. `0` disables read mixing. |
| `--json` | Emit machine-readable JSON. |

## sqlite_query_benchmark.py

**What it does:** Measures read-heavy event-store query behavior over large
synthetic event volumes.

**Who uses it:** Framework developers and performance investigators.

**Process:** Run when report, inventory, audit, or event query paths feel slow
or after adding indexes/query helpers.

**Common usage:**

```bash
PYTHONPATH=. python3 scripts/sqlite_query_benchmark.py --events 100000 --repetitions 5
PYTHONPATH=. python3 scripts/sqlite_query_benchmark.py --database /tmp/bywaf-query.sqlite3 --json
```

**Arguments:**

| Argument | Meaning |
| --- | --- |
| `--database PATH` | Database path. Defaults to a temporary file. |
| `--events N` | Minimum synthetic events to populate. Defaults to `100000`. |
| `--repetitions N` | Query repetitions per measured path. Defaults to `5`. |
| `--payload-bytes N` | Payload bytes in each synthetic event. Defaults to `128`. |
| `--json` | Emit machine-readable JSON. |

## Package Build Scripts

**What they do:** Build release package artifacts.

**Who uses them:** Release maintainers and packagers.

**Process:** Run during release preparation or package smoke testing.

| Script | Purpose | Arguments |
| --- | --- | --- |
| `scripts/build_pip_package.sh` | Build Python package artifacts. | None documented. |
| `scripts/build_deb_package.sh` | Build a Debian package. | None documented. |
| `scripts/build_rpm_package.sh` | Build an RPM package. | None documented. |
| `scripts/build_release_packages.sh` | Run the release package build set. | None documented. |

## Manual Test Helpers

Manual helpers are for controlled local validation. Do not use live third-party
targets unless the assessment is explicitly authorized.

### fake_telnet_service.py

**What it does:** Starts a controlled local Telnet-like service.

**Who uses it:** Maintainers and plugin developers testing network behavior.

**Common usage:**

```bash
python3 scripts/fake_telnet_service.py --host 127.0.0.1 --port 2323
```

**Arguments:**

| Argument | Meaning |
| --- | --- |
| `--host HOST` | Host/interface to bind. Defaults to `127.0.0.1`. |
| `--port PORT` | Port to listen on. Defaults to `2323`. |
| `--hold-seconds N` | How long to hold connections. Defaults to `3.0`. |

### manual_portscanner_flow.py

**What it does:** Runs a controlled manual portscanner flow against an
authorized local target.

**Who uses it:** Maintainers and plugin developers validating scanner behavior.

**Common usage:**

```bash
PYTHONPATH=. python3 scripts/manual_portscanner_flow.py --target 127.0.0.1 --ports 2323
```

**Arguments:**

| Argument | Meaning |
| --- | --- |
| `--target HOST` | Authorized DNS name or host to scan. Defaults to `127.0.0.1`. |
| `--ports LIST` | Comma-separated ports to scan. Defaults to `2323`. |
| `--arguments TEXT` | Nmap arguments. Defaults to `-Pn -sT -sV`. |
| `--database PATH` | Database path to create/use. |

### Manual `.bywaf` Flows

| Script | Purpose | Arguments |
| --- | --- | --- |
| `scripts/manual_finding_report_flow.bywaf` | Scripted REPL flow for finding/report review behavior. | Loaded through Bywaf script execution. |
| `scripts/manual_portscanner_flow.bywaf` | Scripted REPL flow for portscanner behavior. | Loaded through Bywaf script execution. |

## Internal Modules

These modules live under `bywaf/tools/`. They are not all direct CLI tools;
many are implementation modules used by `scripts/` wrappers, tests, or other
tool modules.

| Module | Used By | Purpose |
| --- | --- | --- |
| `architecture/` | `scripts/architecture_metrics.py`, tests | Architecture metrics package; `python -m bywaf.tools.architecture` delegates to the script-compatible CLI. |
| `architecture/formatting.py` | `architecture/__init__.py`, tests | Human-readable formatting for source and documentation metrics. |
| `architecture/graph.py` | `architecture/__init__.py` | Import graph normalization and cycle detection helpers. |
| `architecture/models.py` | architecture metric modules | Data classes for source and repository-level architecture metrics. |
| `architecture/report.py` | `architecture/formatting.py` | Source architecture report section assembly. |
| `architecture/report_sections.py` | architecture and documentation report modules | Shared ranked-section text formatting helpers. |
| `architecture/source.py` | `architecture/__init__.py` | Source-code LOC, complexity, documentation-pressure, and security-surface metrics. |
| `documentation_report.py` | `architecture/formatting.py` | Documentation metrics and impact report rendering. |
| `documentation_metrics.py` | `architecture/__init__.py` | Markdown size, link, stale-term, duplicate-heading, and audience-mixing metrics. |
| `bundled_plugin_manual_check.py` | `scripts/bundled_plugin_manual_check.py`, tests | Bundled plugin manual drift detection. |
| `plugin_check/` | `scripts/plugin_check.py`, tests | Static plugin source analysis package; `python -m bywaf.tools.plugin_check` delegates to the script wrapper. |
| `plugin_check/helpers.py` | `plugin_check/visitor.py`, `plugin_check/diagnostics.py` | AST helper functions for capability and risky-API inference. |
| `plugin_check/llm_render.py` | `plugin_check/render.py`, `scripts/plugin_check.py` | LLM-oriented checker feedback rendering. |
| `plugin_check/model.py` | plugin checker package modules | Data classes for capability evidence and diagnostics. |
| `plugin_check/visitor.py` | `plugin_check/__init__.py` | AST visitor for capability, emit, and diagnostic inference. |
| `plugin_check/render.py` | `scripts/plugin_check.py` | Human-oriented checker output rendering and compatibility facade. |
| `plugin_check/graph_render.py` | `plugin_check/render.py` | Manifest relationship graph output rendering. |
| `plugin_manifest.py` | manifest generation workflows | Manifest generation helpers. |
| `plugin_parser_contract.py` | `scripts/plugin_check.py` | Parser-vs-metadata diagnostics for commandlet arguments and options. |
| `plugin_submission.py` | `scripts/plugin_check.py` | Zip/directory submission materialization in temporary checkouts. |
| `sqlite_contention_benchmark.py` | `scripts/sqlite_contention_benchmark.py` | SQLite contention benchmark implementation. |
| `sqlite_query_benchmark.py` | `scripts/sqlite_query_benchmark.py` | SQLite query benchmark implementation. |

## Adding A New Tool

When adding a new tool:

1. Prefer a small `scripts/` wrapper for human use.
2. Put nontrivial implementation logic under `bywaf/tools/`.
3. Add focused tests for parser behavior and core logic.
4. Document the tool here with audience, process, examples, and arguments.
5. Link it from [Testing](TESTING.md), [Performance](PERFORMANCE.md), or plugin
   author docs when it becomes part of a standard workflow.
