# Changelog

All notable project changes are tracked here. Bywaf is still pre-1.0 software,
so compatibility may change between testing releases.

## Unreleased

Last updated: 2026-05-17 21:07:52 EDT

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

- Added framework-owned `--plan` and `--yes` handling with auditable
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
