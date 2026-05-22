# Bywaf Design Notes

These notes describe framework decisions that are still being refined. They are
more specific than `TODO.md`, but less stable than the public usage guide.

For canonical definitions of runtime terms such as job, pipeline, run, local
ID, serial, event, topic, commandlet, and capability, see `TERMINOLOGY.md`.
For the stable architecture model, see `RUNTIME_MODEL.md`, `EVENT_MODEL.md`,
`CAPABILITY_MODEL.md`, `SYSTEM_BLOCK_DIAGRAM.pdf`, and
`SYSTEM_DATAFLOW_DIAGRAM.pdf`.

## Document Index

- [Framework Request IPC](#framework-request-ipc)
- [Cooperative Runtime Control](#cooperative-runtime-control)
- [Plugin Capability Model](#plugin-capability-model)
- [Framework Notes](#framework-notes)
- [At-File Argument Expansion](#at-file-argument-expansion)
- [Command Input Normalization](#command-input-normalization)
- [Open Design Questions](#open-design-questions)

## Framework Request IPC

Plugins should not directly control interpreter-owned behavior such as terminal
output, paging, prompt changes, password prompts, job control, or future GUI/web
actions. Plugins also should not directly launch local OS processes with
`subprocess`, `os.system`, or `os.spawn*`. Instead, a plugin writes a framework
request event to the SQLite event store. The active frontend/framework validates
the request, performs or denies it, and writes an auditable outcome event.

The current request helpers are:

- `context.output(text)`: writes `framework.console.output.requested`
- `context.alert(message)`: writes `framework.console.alert.requested`
- `context.page_file(path)`: writes `framework.file.page.requested`
- future `context.process.run(argv)`: writes `framework.process.run.requested`
- `context.request(topic, payload)`: advanced low-level request escape hatch
- `context.events`: mediated event-bus reads and writes for plugin code

Current framework-owned outcomes include:

- `console.output`
- `console.alert`
- `console.page`
- `process.run`
- `shell.prompt.updated`
- `framework.request.denied`

### Request Shape

Framework requests should use a predictable payload shape:

```text
{
  "source": "commandlet-name",
  "job_id": 1,
  "pipeline_id": "pipeline-...",
  "command_run_id": "command-...",
  "...": "request-specific fields"
}
```

The event row already carries `source`, `pipeline_id`, `command_run_id`, and
`parent_command_run_id`, so payload copies are convenience fields for frontend
handlers and human inspection. The event row remains the authoritative scope.

Every successful framework action should include the request event ID:

```text
{
  "request_event_id": 123,
  "...": "outcome-specific fields"
}
```

Denied requests should always become:

```text
framework.request.denied
{
  "request_event_id": 123,
  "request_topic": "framework.file.page.requested",
  "reason": "file paging requires a foreground commandlet"
}
```

### Naming Convention

Use this convention for new request topics:

```text
framework.<domain>.<action>.requested
```

Examples:

- `framework.console.output.requested`
- `framework.console.alert.requested`
- `framework.file.page.requested`
- `framework.secret.prompt.requested`
- `framework.confirm.requested`
- `framework.job.cancel.requested`
- `framework.pipeline.kill.requested`
- `framework.process.run.requested`

Outcome topics should describe what happened, not that it was requested:

- `console.output`
- `console.alert`
- `console.page`
- `secret.provided`
- `job.cancelled`
- `pipeline.killed`
- `process.run`
- `framework.request.denied`

### Frontend Contract

The terminal REPL, a future GUI, and a future web frontend should all consume
the same request topics. Each frontend can render the same request differently:

- Terminal `framework.file.page.requested`: run `less` when interactive, print
  text when noninteractive.
- GUI `framework.file.page.requested`: open a file viewer panel.
- Web `framework.file.page.requested`: render a paged text view in the browser.

This lets commandlet code stay frontend-neutral.

## Cooperative Runtime Control

Runtime mutation should be commandlet-mediated. If an operator asks to remove a
host or target from an in-flight scanner, the framework should not reach into a
plugin-owned list and edit it directly. Instead, the framework should persist a
structured control request scoped to the job, pipeline, or command run. The
commandlet is responsible for applying that request to pending work and for
emitting an outcome event describing what it skipped, removed, or ignored.

This matters for pause semantics:

- A soft-paused commandlet is still running cooperatively, so it can observe
  target-removal requests immediately and update its pending queue.
- A hard-paused commandlet is suspended at the OS/process level, so it cannot
  observe anything until it resumes. The framework should persist control
  requests while the process is suspended, and the commandlet should check for
  pending requests before taking more work after resume.

Already-emitted findings remain append-only audit evidence. Runtime mutation
changes future work only; it should not rewrite prior host, port, artifact, or
finding events.

## Plugin Capability Model

Bywaf plugins are local Python code, so capability declarations are not a
sandbox by themselves. They are still useful because they make plugin behavior
auditable, reviewable, and eventually enforceable.

The current implementation is audit-first:

- Plugins declare intended capabilities.
- The framework records capability use and missing declarations as
  `plugin.capability.used` and `plugin.capability.missing`.
- Operators can inspect what a plugin did.
- Enforcement can be added later without redesigning the plugin API.

### Capability Declaration

Capabilities are declared on `CommandSpec`. A commandlet-level declaration is
the most precise starting point:

```python
CommandSpec(
    name="http_probe",
    description="Probe HTTP endpoints.",
    consumes=("port.open",),
    emits=("http.endpoint",),
    capabilities=(
        "db.read:port.open",
        "db.write:http.endpoint",
        "network.connect",
        "framework.console.alert",
        "framework.console.output",
    ),
)
```

Provider-level capabilities can come later when a plugin package needs shared
declarations for many commandlets.

### Capability Names

Use coarse names for implementation simplicity, with optional resource suffixes
where useful:

- `db.read:<topic>`
- `db.write:<topic>`
- `db.raw`
- `framework.console.output`
- `framework.console.alert`
- `framework.file.page`
- `framework.prompt.change`
- `framework.secret.prompt`
- `framework.job.control`
- `filesystem.read`
- `filesystem.write`
- `network.connect`
- `network.listen`
- `process.run`
- `process.spawn`

Topic capabilities are implied from `CommandSpec.consumes` and
`CommandSpec.emits`. Framework request capabilities align with the helper
methods and request topics used by the commandlet.

Normal plugins should use `context.events` instead of raw `context.db`.
`context.events.publish()` records `db.write:<topic>`, and
`context.events.fetch()` / `context.events.query()` record `db.read:<topic>`.
Raw `context.db` remains available for privileged/internal framework
commandlets while the API transitions. Accessing it records `db.raw`, and
commandlets that intentionally need it should declare `db.raw`.

Plugins that need to execute external tools should declare `process.run` and
use `context.process`. `process.spawn` is reserved for long-lived detached
processes and should be treated as higher risk.

### Framework-Mediated Process Execution

External tool wrappers are useful, but direct subprocess use makes plugin
behavior harder to audit and eventually enforce. The plugin-facing blocking API
is:

```python
result = context.process.run(
    ["nmap", "-sn", "127.0.0.1"],
    timeout=30,
)
```

The framework translates that into:

```text
framework.process.run.requested
process.run
framework.request.denied
```

Request payloads should include at least:

- `argv`
- `cwd`
- `timeout`
- `source`, `job_id`, `pipeline_id`, and `command_run_id`

Outcome payloads should include at least:

- `request_event_id`
- `argv`
- `returncode`
- `stdout`
- `stderr`
- `ok`

Long-running tools can use the streaming API:

```python
for chunk in context.process.stream(["tool", "--verbose"]):
    if chunk.stream == "stdout":
        parse_or_buffer(chunk.text)
    else:
        context.output(chunk.text)
```

The framework records:

```text
framework.process.stream.requested
process.started
process.stdout
process.stderr
process.exited
```

## Framework Notes

`note=` is a framework-owned stage selector. The runner removes it before
commandlet argument parsing, then writes a `note.attached` event once the stage
has job, pipeline, and command-run IDs. This keeps note behavior consistent for
all commandlets and avoids plugin-specific note parsing.

If `note=` is the final selector in a command stage, it consumes the rest of
that stage text without requiring quotes. In a pipeline, the note ends at the
pipe boundary.

The `note` runtime commandlet reads `note.attached` events by `run=`,
`pipeline=`, or `job=` selector. Console output and `file=` exports use
timestamp-first text lines so notes can be reviewed or copied into reports.
Notes are append-only; `note add ... text=...` creates another event rather
than modifying earlier context.

## At-File Argument Expansion

At-file expansion is framework-level command syntax, not plugin-specific
parsing. The runner expands `@file`, `@raw:file`, and `@lines:file` after
pipeline parsing and before commandlet `run()` receives arguments. `@@value`
escapes a literal leading `@`.

The framework records `framework.argument.expanded` with the command-run scope,
path, expansion mode, and number of produced arguments. File reads are audited
through the normal capability audit path.

## Command Input Normalization

The shell and script loader normalize physical input into logical commands
before dispatch. A physical line ending with an unescaped trailing backslash is
joined with the next line. After continuation joining, unquoted semicolons split
the logical line into sequential commands. Quoted semicolons remain part of the
argument text.
- `cwd`
- `exit_code`
- output sizes or hashes
- optionally bounded stdout/stderr text when capture is requested

Plugins should not use a shell string by default. Shell execution, if supported
at all, should require a separate higher-risk capability.

### Audit Events

Audit mode produces capability events without blocking execution:

```text
plugin.capability.used
{
  "commandlet": "http_probe",
  "capability": "network.connect",
  "declared": true,
  "request_event_id": null
}
```

```text
plugin.capability.missing
{
  "commandlet": "less",
  "capability": "framework.file.page",
  "request_event_id": 123
}
```

This gives the operator a clear path to review whether a plugin is behaving as
advertised.

### Enforcement Modes

Capability enforcement should be configurable:

```text
capabilities.mode=off
capabilities.mode=audit
capabilities.mode=warn
capabilities.mode=enforce
```

Recommended progression:

1. `off`: no checks.
2. `audit`: record capability use and missing declarations.
3. `warn`: record and print warnings for missing declarations.
4. `enforce`: deny undeclared framework requests and eventually restrict DB
   reads/writes through framework-owned APIs.

Audit-only capability tracking is the current behavior.

### Practical Limits

Capabilities do not secure arbitrary trusted Python code by themselves. Raw
`context.db` access is still available during the transition for privileged
framework commandlets, and Python cannot reliably sandbox hostile in-process
code. Strong enforcement requires normal plugins to use `context.events`, a
stricter plugin API, subprocess isolation, or both.

The near-term goal is therefore:

- make intended behavior explicit,
- make actual behavior visible,
- route sensitive framework actions through auditable request handlers,
- move toward narrower APIs before promising hard isolation.

## Open Design Questions

- Should `CommandSpec.consumes` and `CommandSpec.emits` automatically imply
  `db.read:<topic>` and `db.write:<topic>` capabilities?
- Should missing capabilities warn by default during development?
- Should third-party plugins be loaded in a separate process with a narrower
  context object?
- Which request topics should be foreground-only?
- Should operator approval be required when a plugin first uses a sensitive
  undeclared capability?
