# TODO

Planning dates are release planning markers, not compatibility commitments.

## Current Release

- Bywaf 0.9.0 testing release: 2026-05-13.

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

- Package Bywaf for system installation, including a normal `bywaf` executable,
  stock plugin directories, and user-local `.bywaf/` state.

## Completed After 0.9.0

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
