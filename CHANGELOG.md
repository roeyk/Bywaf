# Changelog

All notable project changes are tracked here. Bywaf is still pre-1.0 software,
so compatibility may change between testing releases.

## Unreleased

### Added

- Added framework-owned file paging requests through `context.page_file()` and
  `framework.file.page.requested` events.
- Added `DESIGN.md` with initial framework request IPC and plugin capability
  model notes.
- Added roadmap candidates to `TODO.md`.

### Changed

- Changed the `less` commandlet to request paging from the framework instead of
  launching terminal paging directly.
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
- Added `bywaf --encrypted` and `bywaf --database <path> --encrypted`.
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
