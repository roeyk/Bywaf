# TODO

Planning dates are release planning markers, not compatibility commitments.

## Current Release

- Bywaf 0.9.1 testing release: 2026-05-18.

## Target: 0.10.0

### Framework Request IPC

- Expand framework-owned request helpers beyond prompt, output, alerts, file
  paging, and process execution when a commandlet needs interpreter-owned
  behavior.
- Add request/response documentation for frontend authors implementing terminal,
  GUI, or web clients.
- Refine the request and outcome conventions in `DESIGN.md`.
- Add request/response helpers for any future long-running framework-owned
  operations that need asynchronous frontend handling.

### Plugin Capability Model

- Decide how strict enforcement should be for trusted local plugins versus
  third-party plugins.
- Add enforcement modes for missing capabilities after audit-only mode has been
  exercised with real plugins.
- Add policy checks for direct process execution and require `process.run` for
  mediated external tool wrappers.
- Split future deep-dive docs from `CAPABILITY_MODEL.md` if needed, such as
  `PLUGIN_TYPES.md`, `PLUGIN_SECURITY_MODEL.md`, and `PLUGIN_PACKAGING.md`.

### External Tool Wrappers

- Add more plugins that wrap established external tools and normalize their
  output into the central event database.
- Prioritize wrappers that remove manual handoffs between scan phases.

### Item: Plugin Packaging

- Define how third-party plugins are packaged, installed, discovered, trusted,
  and upgraded independently from the core Bywaf package.
- Preserve explicit plugin loading as the scaling model: Bywaf should be able
  to ship or discover large plugin catalogs without importing every plugin at
  startup, following the same practical pressure Metasploit has with thousands
  of modules.
- Decide whether Bywaf should auto-discover user-local and system-wide plugin
  config files, or keep those paths explicit until the plugin trust model is
  stricter.
- Continue refining stock plugin directory/search-path behavior for future
  system-wide plugin directories.
- Document recommended plugin package layouts for pip, Debian, RPM, and
  unpacked local development plugins.

### Item: MVP Plugin Suite

- Build a small, rock-solid plugin suite that demonstrates the main plugin
  integration styles: native user-facing, library-backed, external-tool
  wrapper, and helper/provider.
- Treat the existing `hostscanner` and `portscanner` commandlets as
  library-backed examples around libnmap/nmap-backed discovery and port
  scanning.
- Treat the table rendering provider as the helper/provider example: it is
  framework-native and mainly exists for other commandlets to use.
- Expand the new native `webfin` plugin into the user-facing native pentesting
  example, and keep `web_fingerprint` plus `scope_audit` as naming/design
  candidates for future native commandlets if they become separate behaviors.
- Keep the Nikto wrapper plugin as the external-tool wrapper example: it
  invokes Nikto through the framework-mediated process API, parses JSON output
  into structured finding and vulnerability events, and consumes upstream HTTP
  endpoint/fingerprint events from the Bywaf event database.
- Treat `eyewitness` and `wifi_scan` as additional external-tool wrapper
  examples covering screenshot artifacts and wireless scan logs.
- Treat `finding_dedupe` as the native finding-normalization step that prepares
  scanner output for a later reporter plugin using the framework table
  provider.
- Add at least one documented end-to-end chain showing discovery, port
  scanning, HTTP probing, screenshots, Nikto scanning, table/report output,
  notes, and artifacts.

### GUI/Web Frontend

- Build a local GUI or web frontend on top of `BywafSession`.
- Render events, jobs, command output, file paging, and framework requests
  without scraping REPL text.

### Job Control

- Add richer cooperative job control such as pause/resume if commandlets can
  support it cleanly.
- Define pause/resume semantics separately from cancel/kill. Current job
  control supports cooperative cancellation and signal-based termination only.
- For future target-removal or target-skip requests, prefer structured control
  signals to commandlets instead of framework mutation of plugin-owned queues.
  Soft-paused commandlets can react immediately; hard-paused OS processes must
  persist the request and check it immediately after resume.
- Improve cancellation tests so background child-process failures do not print
  noisy tracebacks during otherwise passing test runs.

### Packaging

- Upload the 0.9.x source and wheel artifacts to TestPyPI, then PyPI, and
  verify installation from PyPI in a clean virtual environment.
- Keep pip, Debian, RPM, and plugin install-path smoke scripts aligned as
  packaging behavior changes.
- Keep user-local state in `~/.bywaf/`; do not package generated local DB,
  history, cache, or virtualenv files.

## Completed After 0.9.0

- 2026-05-18: Added persistent release builders for pip source/wheel artifacts
  under `dist/` and RPM artifacts under `dist/rpm/`.
- 2026-05-18: Added persistent Debian release artifacts under `dist/deb/` and
  a tag-driven GitHub Actions workflow that builds, smoke-tests, uploads, and
  attaches pip, Debian, and RPM artifacts to GitHub Releases.
- 2026-05-18: Built and smoke-tested pip source/wheel distributions, the
  Debian package, and RPM source/noarch packages from the packaging scaffolds.
- 2026-05-18: Verified packaged installs expose a normal `bywaf` executable,
  include `bywaf/plugins/plugins.json`, and include bundled stock commandlet
  modules.
- 2026-05-18: Added the initial Debian packaging scaffold and declared packaged
  plugin metadata.
- 2026-05-18: Added regression coverage and a reusable smoke script for
  user-local and system-wide shaped plugin roots.
- 2026-05-18: Added an installed-package smoke wrapper for validating an
  installed `bywaf` executable.
- 2026-05-13: Added audit-only plugin capability declarations and
  `plugin.capability.used` / `plugin.capability.missing` events.
- 2026-05-13: Added pipeline control plus `kill` / `cancel` selector
  commandlets for jobs and pipelines.
- 2026-05-13: Added class-based commandlet metadata decorators for plugin
  authors.
- 2026-05-14: Converted bundled commandlets to class-based metadata decorators.
- 2026-05-13: Added framework-owned paging through `context.page_file()` and
  `framework.file.page.requested`.
- 2026-05-14: Added `audit show` / `audit export` for JSON, JSONL, and SQLite
  audit handoff.
- 2026-05-14: Added framework-mediated process execution through
  `context.process.run()` and line-oriented `context.process.stream()`.
- 2026-05-17: Added framework-level `note=` parsing and `note.attached` audit
  events for command runs.
- 2026-05-17: Added `note` commandlet for timestamped note review and
  `file=` export by run, pipeline, or job.
- 2026-05-17: Added append-only post-hoc notes with `note add`.
- 2026-05-17: Added framework-level at-file expansion and filename completion
  for `@`, `@@`, `@raw:`, and `@lines:`.
- 2026-05-17: Added backslash command continuation and semicolon command
  sequences.
- 2026-05-17: Added `pipelines` alias and timestamp-first history display.
- 2026-05-17: Added canonical architecture documents for terminology, runtime,
  events, capabilities, and system block/dataflow diagrams.
