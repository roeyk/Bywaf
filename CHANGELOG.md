# Changelog

All notable project changes are tracked here. Bywaf is still pre-1.0 software,
so compatibility may change between testing releases.

## [0.10.0] - 2026-05-19

Last updated: 2026-05-20 16:55:00 EDT

### 2026-05-20 16:55:00 EDT

#### Added

- Added explicit startup trust bypass flags for external plugin development:
  `--allow-unsigned-plugins`, `--allow-missing-plugin-keys`, and
  `--allow-mismatched-plugin-keys`.
- Added provider-owned trigger specs through the plugin API.
- Added trigger lifecycle audit events: `framework.trigger.enabled`,
  `framework.trigger.fired`, and `framework.trigger.disabled`.
- Added runtime signed plugin catalog verification for filesystem plugin
  roots through `--plugin-catalog` and `--plugin-catalog-key`.
- Added plugin catalog trust audit events:
  `plugin.catalog.verified`, `plugin.catalog.rejected`,
  `plugin.catalog.entry.verified`, and `plugin.catalog.entry.rejected`.
- Added the `triggers` built-in command for listing provider-owned trigger
  rules.
- Added `--allow-unsigned-plugin-manifests` as the narrow development bypass
  for future framework-signed plugin manifests.
- Added `scripts/plugin_check.py` for validating filesystem plugin packages
  outside the Bywaf interpreter.

#### Changed

- Filesystem plugin packages now require `bywaf.plugin.toml`; the manifest is
  enforced as package metadata before commandlets are exposed.
- Trigger provider metadata is now declared in `[[triggers]]` manifest rows and
  enforced against plugin `triggers()` output before rules are exposed.
- Trigger cursor state now uses provider-scoped trigger identities so separate
  providers can reuse local trigger names without colliding.
- Added canonical config digest helpers for future framework-managed config
  signatures; comments and formatting are ignored, and config lists are treated
  as unordered sets.
- Tightened plugin manifest and catalog metadata parsing so trust metadata
  rejects wrong TOML value types instead of coercing them.
- Added `--allow-untrusted-plugins` as the broad command-line argument for
  explicitly waiving plugin signature, missing-key, and key-mismatch checks;
  kept `--force-plugins` as a hidden compatibility alias.
- Changed automatic watchdog startup to fire from the watchdog plugin's
  network capability trigger instead of starting unconditionally for every
  interactive session.
- Added persisted per-trigger cursors, action modes, payload equality
  predicates, and self-trigger suppression for trigger providers.
- Extended the plugin catalog builder so external filesystem plugin roots can
  be cataloged with `--plugin-root` and `--plugin-config`, including trigger
  metadata read from sidecar manifests without importing plugin code.
- Fixed filesystem catalog generation for single-segment plugin entries such
  as `default_plugins = ["myplugin"]`.

### 2026-05-19 19:10:00 EDT

#### Added

- Added a plugin catalog signing smoke script that exercises the maintainer CLI
  flow end to end: build catalog, generate encrypted Ed25519 keys, sign, and
  verify with `--check-tree`.
- Added a unittest wrapper for the smoke script, skipped automatically when the
  optional `cryptography` dependency is unavailable.

### 2026-05-19 19:08:00 EDT

#### Changed

- External filesystem plugin loading now refuses by default with a warning when
  plugin catalog trust is not verified.
- Added explicit force bypasses for reviewed local development plugins:
  `load --force plugin=...` in the REPL and `--force-plugins` for startup
  plugin roots/configs.

### 2026-05-19 18:52:00 EDT

#### Added

- Added plugin catalog tree verification so signed catalogs can also be checked
  against the current bundled plugin source and sidecar manifest hashes.
- Added regression tests for plugin catalog build, tree checking, signing,
  verification, and tamper rejection.

#### Changed

- Documented the maintainer-side plugin catalog signing workflow in the README,
  usage guide, and plugin author guide.

### 2026-05-19 18:35:00 EDT

#### Added

- Added the `bundle` runtime commandlet for creating, populating, sealing,
  verifying, listing, showing, and exporting evidence bundles.
- Added bundle sealing with deterministic manifest hashing and optional
  Ed25519 signatures through the user keyring.
- Added JSON bundle export with audit records, artifact metadata, and Base64
  artifact bodies.
- Added a bundle signing user-flow script and unit coverage for signed bundle
  creation, verification, and export.

### 2026-05-19 18:08:00 EDT

#### Added

- Added executable user-flow regression scripts under `tests/user_flows`.
- Added `tests/scripts/run_user_flow.py`, which runs `.bywaf` scripts against a
  temporary database and checks `# EXPECT:` and `# EXPECT-EVENT:` assertions.
- Added initial user flows for runtime basics and artifact provenance.

### 2026-05-19 17:50:00 EDT

#### Added

- Added a `key` runtime commandlet for listing, generating, importing,
  exporting, removing, and testing signing/verification keys.
- Added user-local key storage under `~/.bywaf/keys`, with encrypted Ed25519
  private keys, public-key metadata, computed signing state, and key-name
  completion hooks for future signed bundle/export commands.

#### Changed

- Added the optional `signing` Python extra for `cryptography`.
- Preserved plugin-owned `name=` selectors for commandlets such as `key`,
  `artifact`, and `search` instead of treating them as run-display names.

### 2026-05-19 15:12:10 EDT

#### Added

- Added `watchdog` as a service-style runtime monitor that emits timeout,
  stall, and error-rate events for active jobs.
- Added automatic session-scoped watchdog startup for interactive sessions,
  with orderly shutdown of that default service on exit.

#### Changed

- `cmds --page` now pages commandlet listings through the framework pager.
- Revised `SYSTEM_BLOCK_DIAGRAM` into a structural component map and kept
  `SYSTEM_DATAFLOW_DIAGRAM` as the data movement view.

### 2026-05-19 14:10:19 EDT

#### Added

- Added one-project-per-database workspaces under `~/.bywaf/projects`.
- Added startup project selection with `bywaf project=<name>` and project
  creation with `bywaf --new project=<name>`.
- Added `project list`, `project info`, `project new`, and `project use` REPL
  commands.
- Added `FAQ.md` with example-first answers for common Bywaf tasks.
- Added FAQ provenance examples for identifying artifact producers, verifying
  artifact integrity, exporting artifacts, securing exports, and inspecting
  pipeline/run events.
- Added `command.run.arguments` audit events so commandlet run parameters are
  visible after framework expansion with declared secret options redacted.
- Added redacted process environment metadata to framework-mediated process
  request events.

#### Changed

- `project use` now switches the active database, config, and history path.
- `project use ... --force` hard-stops active jobs before switching and audits
  the forced stop in the old project database.
- Documented `signal` as an advanced explicit runtime-control form while
  keeping friendly commands as the recommended user interface.
- Artifact listings now show the producing `commandlet=` field.
- Run variable display now redacts persisted secret references with their
  fingerprint instead of printing opaque secret tokens.

### 2026-05-19 13:40:37 EDT

#### Added

- Added normal GitHub Actions CI for unit tests, coverage artifacts, Ruff,
  Pyright, Bandit, and pip-audit on pushes, pull requests, and manual runs.
- Added CodeQL analysis for Python on pushes, pull requests, weekly schedule,
  and manual runs.
- Added Dependabot configuration for GitHub Actions and Python dependency
  updates.
- Added coverage.py configuration in `pyproject.toml`.

### 2026-05-19 12:46:00 EDT

#### Added

- Added commandlet option metadata for `secret=True` and marked bundled
  password/API-key options as secret.
- Added HMAC-based secret fingerprints and in-memory secret references for
  manual `vars password=...` style assignments.
- Added `context.secrets` so commandlets can explicitly resolve opaque secret
  references through an audited framework API.
- Added manifest `secret_options` metadata, enforcement against Python
  `OptionSpec.secret`, and a `bywaf-plugin-manifest` developer helper.
- Added persistent database-backed secret storage so secret variables survive
  restart, with a plaintext database warning when DB encryption is not active.

#### Changed

- Redacted obvious secret `name=value` assignments in REPL command history and
  `vars` output while preserving an audit-safe fingerprint.
- Updated bundled credential-aware commandlets to use `context.secrets` and
  declare `framework.secret.resolve`.
- Redacted known in-memory secrets from process audit argv and emitted
  `process.secret.argv` warnings when process-wrapped plugins pass resolved
  secrets as command-line arguments.

### 2026-05-18 18:29:12 EDT

#### Added

- Added explicit persistence contracts for event, runtime, artifact,
  maintenance, and variable stores.
- Added `PERSISTENCE_MODEL.md` to document store boundaries and default
  SQLite-backed implementations.
- Added context accessors for narrow event, runtime, and maintenance store
  access.
- Added TOML support for human-authored plugin lists, filesystem plugin
  defaults, and session variable config files.
- Added bundled `bywaf/plugins/plugins.toml` while keeping legacy
  `plugins.json` compatibility.
- Added filesystem plugin manifest support with `bywaf.plugin.toml`, including
  authoritative commandlet exposure and implementation traits for native,
  library-backed, process-wrapped, and service plugins.
- Added bundled plugin sidecar manifests such as `nikto.plugin.toml` and
  enforced those manifests during package plugin discovery.
- Added commandlet-level manifest capability declarations, validation against
  Python `CommandSpec.capabilities`, and plugin-load audit details including
  manifest path, SHA-256 hash, traits, roles, and capabilities.

#### Changed

- Moved `Subscription` into a neutral subscriptions module and re-exported it
  through the existing DB import path.
- Migrated runtime commandlets away from raw DB access for ordinary
  runtime/event/artifact operations.
- Replaced simple value-dispatch `match` blocks with dispatch tables for DB
  actions, audit actions/export formats/bounds, artifact actions/completions,
  rendering formats, nmap backend handlers, finding report sources, finding
  dedupe payload/alert builders, framework request capabilities, at-file
  expansion modes, and artifact count scopes.
- Added role-specific runner store properties and migrated the public API plus
  user-facing runtime/event display paths to event, runtime, and maintenance
  store roles where concrete SQLite access is not required.
- Changed default session config path to `.bywaf/config.toml`; legacy JSON
  config files can still be loaded and saved explicitly.
- Hardened `CommandContext` variable exposure so commandlets receive a scoped
  variable facade instead of the raw session `VarStore`, and removed public raw
  store access from `ScopedVarStore`.

## [0.9.2] - 2026-05-18

Testing release focused on producing unambiguous release artifacts from the
fixed package workflow.

### 2026-05-18 16:25:00 EDT

#### Fixed

- Fixed release workflow dependency installation for Python package builds.
- Fixed Debian build dependencies in GitHub Actions.
- Fixed RPM smoke tests on Ubuntu builders by skipping RPM database dependency
  checks and normalizing Python installation paths into a stable RPM site
  directory.
- Confirmed pip, Debian, and RPM package artifacts can be built and smoke-tested
  from the same release workflow.

## [0.9.1] - 2026-05-18

Testing release focused on plugin breadth, finding/report workflows,
completion regressions, runtime polish, and package release automation.

### 2026-05-18 14:39:43 EDT

#### Added

- Added a generated completion regression suite covering commandlet names,
  binary `--flag` options, value-bearing `name=` arguments, choice values,
  filespec completions, `$variable` references, runtime selectors,
  pipe-position commandlet completion, and prompt-toolkit display labels.
- Added PTY-level readline completion smoke tests that launch the real REPL,
  type partial commands, send Tab, and verify the terminal text for pipe
  command completion, filespec arguments, and `--` prefix handling.

#### Changed

- Completion now follows the command syntax rule: `--flag` is for binary flags,
  while `name=value` is for arguments or selectors that take a value.
- Added `BYWAF_INPUT_READER=readline` for deterministic interactive completion
  smoke tests while keeping prompt-toolkit as the default interactive reader.

### 2026-05-18 14:17:22 EDT

#### Added

- Added the native `finding_report` analysis commandlet. It reads normalized
  dedupe findings or raw tool vulnerability events and renders a findings table
  through the framework table provider.
- Added `finding_report export=...`, which infers the table output format from
  the filename suffix and attaches the exported report as an artifact.

#### Changed

- Pipeline stages now pass directly-published declared output events to the
  next stage, not only yielded payload events. This lets
  `finding_dedupe | finding_report` report on the immediately preceding
  commandlet's findings.

### 2026-05-18 14:01:37 EDT

#### Added

- Added the native `finding_dedupe` analysis commandlet. It consumes
  vulnerability/finding events, emits `finding.new`, `finding.duplicate`,
  `finding.updated`, and `finding.merge_candidate`, and can write/attach JSON
  or Markdown dedupe summaries for later reporting.

#### Changed

- Documented the dedupe model: exact standardized identifiers first, then
  target and evidence fingerprints, with fuzzy text matching reserved for
  reviewable merge candidates.

### 2026-05-18 12:40:40 EDT

#### Added

- Added initial library-backed commandlets for optional Python pentesting
  libraries: `dns_lookup` using dnspython, `shodan_lookup` using Shodan,
  `ssh_probe` using Paramiko, `snmp_get` using pysnmp, `ldap_probe` using
  ldap3, `smb_probe` using Impacket, and `yara_scan` using yara-python.
- Added `context.events.follow(...)` for finite second-stage listeners. A
  listener can now follow scoped upstream events and terminate after its parent
  command run has completed or failed and all matching events are drained.
- Added `command.run.started`, `command.run.completed`, and
  `command.run.failed` lifecycle events around commandlet execution.

#### Changed

- `portscanner --listen` now uses the framework event-follow helper instead of
  its own polling loop.
- `wifi_scan` examples now use Bywaf-style `interface=` and `duration=`
  arguments.

### 2026-05-18 12:24:49 EDT

#### Changed

- Artifact storage now mirrors the main database encryption mode. Encrypted
  main databases use encrypted artifact databases with the same passphrase;
  plaintext main databases use plaintext artifact databases instead of
  rejecting artifact attachment.

### 2026-05-18 12:12:28 EDT

#### Added

- Added the `eyewitness` HTTP screenshot wrapper commandlet. It runs
  EyeWitness through the framework process API, emits `eyewitness.screenshot`
  and `web.screenshot` events, writes screenshots under a durable output
  directory by default, and attaches screenshots as encrypted artifacts when
  available.
- Added the `wifi_scan` wireless wrapper commandlet. It runs a Kismet-style
  scan through the framework process API, writes logs under a durable output
  directory by default, attaches output files when possible, and emits
  `wifi.network` and `kismet.network` events from JSON output.
- Added `filename=` to `search` and `artifact search`, with `--regexp` support,
  so source filenames can be searched separately from human artifact names.

### 2026-05-18 12:02:07 EDT

#### Added

- Added the `nikto` HTTP wrapper commandlet. It runs Nikto through the
  framework-mediated process API, reads JSON output, emits `nikto.finding`,
  `vulnerability.found`, and `vulnerability.potential` events, and attempts to
  attach raw Nikto JSON as an encrypted artifact when artifact storage is
  available.

#### Changed

- Documented Nikto as the MVP external-tool wrapper plugin and added it to the
  HTTP workflow examples.

### 2026-05-18 09:52:25 EDT

#### Changed

- Renamed the Plugin Packaging and MVP Plugin Suite tracker entries as explicit
  `Item:` sections so they read as standalone tracker items rather than only
  category headings.

### 2026-05-18 09:47:16 EDT

#### Added

- Added the native `webfin` HTTP fingerprinting commandlet. It consumes
  `http.endpoint` events or probes explicit targets, emits `web.fingerprint`,
  and reports lightweight technology tags plus web observations.

#### Changed

- Documented the native web fingerprinting chain:
  `hostscanner | portscanner | http_probe | webfin`.

### 2026-05-18 09:42:12 EDT

#### Changed

- Split plugin packaging into its own tracker section, separate from core
  package release mechanics.
- Added an MVP plugin suite tracker section covering native user-facing,
  library-backed, external-tool wrapper, and helper/provider plugin examples,
  including Nikto wrapper planning and an end-to-end chaining example.

### 2026-05-18 09:33:46 EDT

#### Added

- Added `scripts/build_deb_package.sh`, which builds local Debian artifacts
  and copies them under `dist/deb/`.
- Added a tag-driven GitHub Actions release workflow that builds pip, Debian,
  and RPM artifacts with the local release scripts, smoke-tests package outputs,
  uploads workflow artifacts, and attaches them to tagged GitHub Releases.

#### Changed

- Updated the all-package release builder to include Debian artifacts.

### 2026-05-18 09:30:33 EDT

#### Changed

- Clarified the packaging tracker: local pip, Debian, and RPM package builds
  are implemented and smoke-tested, while TestPyPI/PyPI upload and GitHub
  release artifact publishing remain open release tasks.

### 2026-05-18 08:46:16 EDT

#### Added

- Added persistent package release builders: `scripts/build_pip_package.sh`
  writes source and wheel artifacts under `dist/`, `scripts/build_rpm_package.sh`
  writes source and noarch RPM artifacts under `dist/rpm/`, and
  `scripts/build_release_packages.sh` runs both.

#### Changed

- Updated packaging documentation to use the release-build scripts instead of
  requiring manual RPM tree setup.

### 2026-05-18 08:36:06 EDT

#### Changed

- Ctrl-C in the interactive REPL now prompts for yes/no confirmation before
  quitting, and confirmed exits still run the normal orderly shutdown path.

### 2026-05-18 08:25:45 EDT

#### Changed

- Shortened runtime list timestamps for jobs, runs, pipelines, and info tables
  to `HH:MM:SS TZ` and hide noisy `job-`, `run-`, and `pipeline-` serial
  prefixes in runtime displays so wide rows are easier to read in a terminal.

### 2026-05-18 08:16:00 EDT

#### Added

- Added pip package metadata polish, including README, license, author, and
  classifier metadata.
- Added `MANIFEST.in` so source distributions include core docs and bundled
  plugin metadata while excluding generated local state.
- Added `tests/scripts/smoke_pip_package.sh` for building and installing the
  wheel in a temporary virtual environment, with `twine check` when available.
- Added an initial RPM spec scaffold under `packaging/rpm/bywaf.spec`.
- Added `tests/scripts/smoke_rpm_package.sh` for building a source RPM and
  noarch binary RPM in a temporary RPM tree.
- Added `tests/scripts/smoke_installed_package.sh` for validating an installed
  `bywaf` executable and its plugin-root behavior.
- Documented local pip, Debian, and RPM package build commands.

### 2026-05-18 08:10:08 EDT

#### Added

- Added regression tests for user-local and system-wide shaped filesystem
  plugin roots using the current explicit `--plugin-root` / `--plugin-config`
  path.
- Added `tests/scripts/smoke_plugin_install_paths.sh`, a reusable smoke script
  that can run against either `python3 -m bywaf` or an installed `bywaf`
  executable through `BYWAF_CMD`.
- Captured the packaging follow-up decision: whether user-local and system-wide
  plugin config files should become auto-discovered, or remain explicit until
  the plugin trust model is stricter.

### 2026-05-18 07:59:26 EDT

#### Added

- Added an initial Debian packaging scaffold under `debian/` for building a
  local `.deb` package with `dpkg-buildpackage`.
- Declared `bywaf/plugins/plugins.json` as package data so packaged installs
  retain the default plugin list.
- Documented the local Debian package build command and required Debian build
  dependencies.

### 2026-05-17 23:19:44 EDT

#### Added

- Added `events`, `events tail`, and `events tail last=N` for inspecting the
  latest event rows, with bare `events` defaulting to the last 25 events.

### 2026-05-17 23:14:36 EDT

#### Added

- Added `vars <name>` lookup for printing a single session variable value,
  using the same active-context scoping as `vars <name>=<value>`.

### 2026-05-17 22:59:17 EDT

#### Changed

- Clarified runtime terminology: pipelines group runs, while jobs supervise
  execution work that may run one or more commandlet invocations.
- Added `end` as a synonym for `kill`; both default to cooperative `--soft`
  behavior and accept `--hard` for forced process termination.
- Restricted `signal` to concrete receivers (`job=`, `run=`, or `serial=` that
  resolves to a job/run) instead of pretending pipelines receive plugin-domain
  signals directly.
- Documented artifact storage as paired with the active encrypted main database
  rather than independently selectable by default.

### 2026-05-17 22:46:56 EDT

#### Changed

- Extended artifact `serial=` handling so attachments can target run,
  pipeline, or job serials while artifact serials continue to select existing
  artifacts.
- Kept artifact provenance one-level deep: artifacts attach to runtime
  entities, not to other artifacts.
- Included assigned runtime names in job and pipeline detail output, matching
  the table listings.

### 2026-05-17 22:06:36 EDT

#### Added

- Added `bywaf.rendering` with structured `Table` and `Column` models plus
  console, Markdown, CSV, JSONL, HTML, DOCX, and XLSX table renderers.
- Added `context.render.table(...)` and kept `context.table(...)` as a
  compatibility wrapper over the structured renderer.
- Added framework/audit handling for `framework.render.table.requested` and
  `render.table` events.

### 2026-05-17 21:42:38 EDT

#### Changed

- Reworked the README opening around the assessment handoff problem, a compact
  Bywaf pipeline example, and a comparison with Bash, Metasploit, Airflow, and
  standalone Python scripts.

### 2026-05-17 21:31:17 EDT

#### Added

- Added `RUNTIME_MODEL.md`, `EVENT_MODEL.md`, and `CAPABILITY_MODEL.md` as
  canonical architecture references.
- Added `SYSTEM_BLOCK_DIAGRAM.pdf`, `SYSTEM_DATAFLOW_DIAGRAM.pdf`, and their
  Typst sources, showing system components plus event/artifact/audit/request
  data flow.

#### Changed

- Folded the plugin integration taxonomy into `CAPABILITY_MODEL.md`, covering
  framework-native, library-backed, external-process wrapper, and native/FFI
  plugin types.

### 2026-05-17 21:27:27 EDT

#### Added

- Added `TERMINOLOGY.md` with canonical definitions for jobs, pipelines, runs,
  local IDs, serials, events, topics, commandlets, plugins, and capabilities.

### 2026-05-17 21:14:00 EDT

#### Changed

- Replaced the framework-owned dry-run flag `--plan` with `--test`.

### 2026-05-17 21:07:52 EDT

#### Changed

- Changed `jobs`, `runs`, and `pipelines` listings to table views with local
  IDs, durable serials, lifecycle state, names, timestamps, and artifact counts.
- Added runtime completion metadata for jobs, runs, and pipelines, including
  serial/source/status context and current artifact counts.

### 2026-05-17 21:01:41 EDT

#### Changed

- Clarified runtime identity as local IDs plus durable serials: local `job=`,
  `run=`, and `pipeline=` numbers are stable inside one database and never
  reused there, while `serial=` remains the portable audit-grade selector.
- Added persisted local ID allocation for runs and pipelines, replacing
  recomputed aliases.
- Added durable job serials to job rows and job lifecycle audit events.

### 2026-05-17 20:39:42 EDT

#### Added

- Added short local IDs for interactive run and pipeline selectors while
  preserving durable serials for audit/provenance lookup.
- Added `show serial=<id>` and serial completion for runtime, artifact, plugin
  load, and script load records.
- Added auditable serials for explicit `load plugin=...` and `load script=...`
  operations, including per-command script audit events.

### 2026-05-17 20:05:09 EDT

#### Added

- Switched interactive TTY input to `prompt_toolkit`, with a readline fallback
  for non-interactive/minimal environments.
- Added completion-menu toolbar help and configurable `Ctrl-Space`
  completion-selection mode.
- Added opt-in WASD completion-menu navigation via
  `completion.wasd-selection=true`.

### 2026-05-17 19:42:03 EDT

#### Added

- Added a `search` commandlet, plus `artifact search`, for fast artifact lookup
  with `name=`, `note=`, and `content=` field queries, optional `--regexp`, and
  `since=`/`until=` time bounds.

### 2026-05-17 08:55:00 EDT

#### Added

- Added framework-owned plan/test and `--yes` handling with auditable
  `plan.requested`, `policy.evaluated`, `plan.approved`, `plan.denied`,
  `plan.repair.applied`, and `plan.repair.denied` events.
- Added `PlanReport`, `PlanItem`, and `PlanRepair` plugin APIs.
- Added an initial hostscanner plan implementation with network allow/deny
  policy checks and per-run prune repair suggestions.

### 2026-05-17 08:24:00 EDT

#### Added

- Added the `signal` runtime commandlet for audited live-control messages:
  `signal <job|pipeline|run>=<id> <action> [--soft|--hard] [key=value ...]`.
- Added `context.signals` helpers so commandlets can read, apply, or ignore
  live-control signals without raw DB polling.

#### Changed

- Routed `pause`, `resume`, `stop`, `cancel`, and `kill` convenience commandlets
  through the same `runtime.signal.requested` audit path.

### 2026-05-17 08:06:47 EDT

#### Added

- Added framework-level `$variable` expansion before commandlet parsing, with
  double-quote expansion, single-quote literal preservation, scoped/global
  variable resolution, and `framework.variable.expanded` audit events.

### 2026-05-17 07:56:14 EDT

#### Changed

- Simplified post-hoc runtime naming to `name run|pipeline|job=<id> name text`;
  `text=` is the explicit keyed form.

### 2026-05-17 04:48:04 EDT

#### Added

- Added runtime naming for pipelines, command runs, and jobs. Pipelines can be
  named inline with `name: command | pipeline`, stages can be named with
  `name=...`, and existing entities can be named with the `name` commandlet using trailing name text.

### 2026-05-17 04:32:17 EDT

#### Added

- Finished artifact provenance support with `artifact replace`, `artifact
  remove`, audited mutation events, and encrypted provenance artifacts for
  framework `@file` expansion when artifact storage is available.
- Extended runtime control commands to accept `run=<id>` selectors and list
  queued resume actions from recorded control events.
- Added active/history runtime listing behavior: `runs`, `jobs`, and
  `pipelines` default to active state, while `--all` shows historical rows with
  `[active]`, `[in progress]`, `[failed]`, or `[completed]` markers. The marker
  format is configurable with `global.listing.active-format=short|long`.

#### Fixed

- Mark active jobs as `stale` on startup when their recorded PID is gone, so
  dead jobs, runs, and pipelines do not appear active after restarting Bywaf.

### 2026-05-17 04:14:50 EDT

#### Changed

- Changed `pipeline attach` replay cursors from `from=` to `since=` for
  terminology consistency. `run=` remains the upstream producer selector.

### 2026-05-17 04:06:50 EDT

#### Fixed

- Fixed startup replay of historical framework request events by initializing
  new shell sessions at the current event high-water mark.
- Rechecked `topics <prefix>` and bounded `audit show` behavior as part of the
  startup-spam bugfix batch.

### 2026-05-17 03:55:02 EDT

#### Added

- Added topics prefix filtering, including clean empty-DB behavior for
  `topics <prefix>`.
- Cleaned completion leaks for prompt/internal REPL words and made `run <tab>`
  complete commandlet pipeline names.
- Added audit `since=` and `until=` selectors plus PDF export and encrypted
  SQLite/PDF export support.
- Added `except=` scanner exclusion lists with file-backed `@lines:` support.
- Added the `use` built-in for commandlet-scoped short variable assignments and
  context-first `vars` completion.
- Added artifact verification cross-checks against both the encrypted artifact
  DB hash and the main audit DB artifact metadata hash.
- Added `pause`, `resume`, and `stop` runtime commandlets for jobs and
  pipelines, with soft behavior by default and explicit hard controls.

### Earlier Unreleased Changes

#### Added

- Added audit-only plugin capability declarations on `CommandSpec`.
- Added `plugin.capability.used` and `plugin.capability.missing` audit events
  for framework requests, selected input topics, emitted DB topics, and selected
  filesystem/network/job/database actions.
- Added `context.events` as the mediated plugin-facing event-bus API for
  audited event publishing, fetching, querying, and topic listing.
- Added `db.raw` capability auditing for privileged raw `context.db` access.
- Added `pipeline`, `kill`, and `cancel` runtime commandlets for pipeline/job
  control with completion-friendly selectors.
- Added class-based commandlet metadata decorators: `@commandlet`,
  `@argument`, and `@option`.
- Documented the policy that external process execution should be routed
  through a future framework-mediated process API instead of direct plugin
  subprocess calls.
- Converted bundled commandlets to class-based metadata decorators.
- Added the `audit` runtime commandlet with `show` and `export` support for
  JSON, JSONL, and SQLite audit handoff.
- Added framework-mediated external process execution through
  `context.process.run()` and line-oriented `context.process.stream()`.
- Added framework-level `note=` selectors that attach audited notes to command
  runs without plugin-specific parsing.
- Added the `note` runtime commandlet to show or save timestamped notes by
  `run=`, `pipeline=`, or `job=` selector.
- Added append-only post-hoc notes with `note add ... text=...` and
  `note add ... file=...`.
- Added encrypted artifact storage with the `artifact` runtime commandlet for
  `attach`, `list`, `save`, and `verify` actions.
- Added `context.artifacts.attach_file()` and `context.artifacts.attach_files()`
  so plugins can attach multiple encrypted evidence files to one run.
- Added structured progress reporting helpers with framework-enforced,
  user-configurable throttling.
- Added `CommandletBase.var_default()` and `values_or_var()` helpers so
  commandlets can consistently use CLI arguments before scoped variables before
  built-in defaults.
- Added framework-level at-file argument expansion with `@file`, `@raw:file`,
  `@lines:file`, and `@@literal`.
- Added backslash command continuation for REPL and script input.
- Added semicolon-separated command sequences.
- Added `pipelines` as a convenience alias for `pipeline list`.
- Added `pipeline attach <pipeline-id> <commandlet> [run=<id>] [since=beginning|now]`
  to attach a background commandlet to an existing pipeline with explicit replay
  semantics.
- Added framework-owned file paging requests through `context.page_file()` and
  `framework.file.page.requested` events.
- Added `DESIGN.md` with initial framework request IPC and plugin capability
  model notes.
- Added plugin type taxonomy guidance to the plugin author guide.
- Added roadmap candidates to `TODO.md`.

#### Changed

- Changed the `less` commandlet to request paging from the framework instead of
  launching terminal paging directly.
- Changed `pipeline list` and the `pipelines` alias to show active pipelines by
  default, with `pipeline list --all` for historical pipelines.
- Changed `history` to support `since=` and `until=` time-window selectors.
- Changed `history` display to show timestamps before commands while preserving
  script-friendly storage.
- Changed background job child-process failures to record `job.failed` when
  possible and exit without dumping raw multiprocessing tracebacks.

## [0.9.0] - 2026-05-13

Initial testing release for the rewritten Bywaf framework.

### Added

- Added the Bywaf Python 3 commandlet framework with a Metasploit-like REPL.
- Added SQLite-backed event storage for commandlet pub/sub workflows.
- Added pipeline execution with `|`, background jobs with `&`, and scoped run,
  pipeline, and parent command IDs.
- Added default plugin groups for discovery, network, HTTP, OS, and storage
  commandlets.
- Added `hostscanner` and `portscanner` commandlets powered by nmap adapters.
- Added HTTP commandlets including `http_headers` and `http_probe`.
- Added OS commandlets `ls`, `cat`, and `less`.
- Added the `plugins` command for loaded plugin providers and `cmds` for
  commandlets grouped by provider.
- Added plugin-owned completion specs for files, paths, options, choices,
  plugins, jobs, topics, runs, and pipelines.
- Added script loading with `load script=<path>`.
- Added session variables with `vars name=value`.
- Added command history with configurable timestamp formatting.
- Added default `.bywaf/` state directories for databases, config, history, and
  local plugins.
- Added save/load support for databases, config, and history.
- Added optional SQLCipher database support through `sqlcipher3-binary`.
- Added `bywaf --encrypt` and `bywaf --database <path> --encrypt`.
- Added encrypted database snapshots with `save --encrypt db=<path>`.
- Added the storage `db` commandlet with `status`, `path`, `checkpoint`, and
  `vacuum`.
- Added the runtime `job` commandlet with `list`, `show`, `cancel`, and `kill`.
- Added `jobs` as an alias for `job list`.
- Added DB-first background job invocation with `job.requested`, `job.claimed`,
  `job.started`, `job.finished`, and `job.failed` audit events.
- Added foreground job lifecycle auditing for normal commandlet execution while
  keeping `db` and `job` management commands direct.
- Added soft-cancellation records and plugin-visible cancellation checks.
- Added scoped plugin variable access through `context.vars`.
- Added per-command-run variable snapshots in SQLite for auditable,
  deterministic background jobs.
- Added audited framework request handling for prompt-change requests.
- Added `BywafSession` as the public Python facade for GUI, web, and automation
  clients.
- Added `context.alert()` framework requests and structured `console.alert`
  events for plugin console output.
- Added `context.request()`, `context.output()`, and `context.table()` helpers
  so plugin authors can use framework-mediated output without direct `print()`.
- Added `CommandContext` metadata accessors plus `require_db()` and
  `require_foreground()` helpers for cleaner plugin guard code.
- Added `CommandletBase` for shared argparse parser setup in commandlets.
- Added `db encrypt`, `db decrypt`, and `db rekey` for active database
  encryption management.
- Added `db new`, `db new --file=<path>`, `db new --encrypt`, and
  `db new --force` for creating and switching to fresh databases.
- Added `db.encryption=sqlcipher` as a default preference for encrypted
  databases created with `db new`.
- Added `README.md`, `USAGE.md`, regenerated `USAGE.pdf`, and
  `PLUGIN_AUTHOR_GUIDE.md`.
- Added unit tests covering parser behavior, plugin execution, completion,
  database storage, nmap adapters, HTTP probing, config handling, and storage
  commandlets.

### Changed

- Changed bundled plugin loading to use `bywaf/plugins/plugins.json` rather
  than loading every plugin module automatically.
- Changed filesystem commands to be plugin-provided commandlets instead of REPL
  built-ins.
- Changed `help <command>` to delegate to commandlet argparse help where
  possible.
- Refactored runner stage execution and job lifecycle auditing into shared
  helpers.
- Refactored framework request dispatch to use a handler table.
- Split SQLite schema and compatibility migrations into `bywaf.db_schema`.
- Split the large runner/app test module into focused test modules.
- Changed `save db=<path>` to be an export/copy operation that does not switch
  the active database.
- Changed database shutdown to checkpoint SQLite WAL state cleanly.
- Improved commandlet alerts so scanners announce discovered hosts and ports
  unless `-s` or `--silent` is used.
- Improved nmap target handling for host ranges such as `192.168.0.1-255` and
  `192.168.1-3.1-255`.

### Fixed

- Fixed crashes for unknown commands in the REPL.
- Fixed crashes when commandlets receive `--help` or invalid arguments.
- Fixed completion behavior for `--` so tab completion does not duplicate the
  prefix.
- Fixed path completion for `load plugin=...`, `load script=...`, and related
  resource commands.
- Fixed pipeline parsing for attached background markers such as
  `hostscanner 127.0.0.1& | portscanner&`.
- Fixed SQLite query construction flagged by Bandit by replacing dynamic SQL
  filters with fixed parameterized predicates.
- Fixed static analysis issues reported by Ruff and Pyright.

### Security

- Added Bandit checks to the regular development validation flow.
- Added optional encrypted database support for sensitive scan/session data.
- Ensured database passphrases are prompted interactively and not written to
  config or history files.
