# TODO

Planning dates are release planning markers, not compatibility commitments.

## Current Release

- Bywaf 0.9.0 testing release: 2026-05-13.

## Target: 0.10.0

### Framework Request IPC

- Expand framework-owned request helpers beyond prompt, output, alerts, and
  file paging when a commandlet needs interpreter-owned behavior.
- Add request/response documentation for frontend authors implementing terminal,
  GUI, or web clients.
- Refine the request and outcome conventions in `DESIGN.md`.

### Plugin Capability Model

- Decide how strict enforcement should be for trusted local plugins versus
  third-party plugins.
- Add enforcement modes for missing capabilities after audit-only mode has been
  exercised with real plugins.

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
- 2026-05-13: Added framework-owned paging through `context.page_file()` and
  `framework.file.page.requested`.
