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

- Add plugin-declared capabilities for sensitive actions such as filesystem
  access, network access, framework requests, and database topic read/write
  access.
- Decide how strict enforcement should be for trusted local plugins versus
  third-party plugins.
- Start with audit-only capability events before enforcing policy.

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

- 2026-05-13: Added framework-owned paging through `context.page_file()` and
  `framework.file.page.requested`.
