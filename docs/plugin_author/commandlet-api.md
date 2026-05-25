# Commandlet API Reference

Reference for commandlet specs, parsing, output, event flow, completion, runtime context, framework requests, embedding, and defaults.

## CommandSpec Fields

`CommandSpec` is the public description of a commandlet:

```python
CommandSpec(
    name="hello",
    description="Say hello and emit a greeting event.",
    usage="hello [name]",
    examples=("hello", "hello world"),
    options=(),
    arguments=(),
    consumes=(),
    emits=("hello.greeting",),
    capabilities=("framework.console.output",),
)
```

Important fields:

- `name`: the command typed in the REPL
- `description`: short human description
- `usage`: command expression shown by help
- `examples`: example invocations
- `options`: option metadata for completion and future introspection
- `arguments`: positional argument metadata for completion
- `consumes`: event topics this commandlet expects as input
- `emits`: event topics this commandlet publishes
- `capabilities`: audit declarations for sensitive behavior

Bywaf currently treats capabilities as audit metadata, not hard sandboxing.
`consumes` and `emits` imply `db.read:<topic>` and `db.write:<topic>` for the
listed topics. Declare other behavior explicitly, such as
`framework.console.output`, `framework.console.alert`, `framework.file.page`,
`filesystem.read`, or `network.connect`.

For class-based commandlets, decorators can remove most of that metadata
boilerplate:

```python
from bywaf.plugin import CommandletBase, argument, commandlet, option

@commandlet(
    name="hello",
    description="Say hello and emit a greeting event.",
    usage="hello [name]",
    examples=("hello", "hello world"),
    emits=("hello.greeting",),
    capabilities=("framework.console.output",),
)
@option("uppercase", "uppercase the greeting", default="false", choices=("true", "false"))
@argument("name", "name to greet", required=False)
class Hello(CommandletBase):
    def run(self, context, args, input_events):
        parser = self.parser()
        parser.add_argument("name", nargs="?", default="world")
        parser.add_argument("--uppercase", choices=("true", "false"), default="false")
        parsed = parser.parse_args(args)
        greeting = f"hello, {parsed.name}"
        if parsed.uppercase == "true":
            greeting = greeting.upper()
        context.output(greeting)
        yield {"name": parsed.name, "greeting": greeting}
```

Decorator order is intentional: Python applies decorators from bottom to top, so
`@argument` and `@option` collect metadata before `@commandlet` builds the final
`CommandSpec`.

Options that carry credentials should be declared with `secret=True`:

```python
@option("password", "SSH password", secret=True)
@option("api-key", "service API key", secret=True)
```

Operators can also set any variable as a secret with `set --secret name=value`.
Bywaf does not guess based on variable names; plain `set password=value` is an
ordinary variable. Explicit secret assignments are redacted in command history
and displayed as `[REDACTED]` with an HMAC fingerprint, so audit trails can
correlate that a secret was supplied without exposing the plaintext in normal
variable display. The plaintext is stored in the active database so it can
survive restart. If the database is encrypted, the secret is protected by that
encryption at rest; if the database is plaintext, Bywaf warns the operator
before storing it.

Do not pass resolved secrets as process arguments. Command-line arguments can
be visible in OS process listings and often end up in tool logs. If a
process-wrapped tool needs a credential or other sensitive value, prefer
environment variables, stdin, or a temporary file with restrictive permissions.
Bywaf redacts known in-memory secrets from process audit events and emits
`process.secret.argv` when it detects a resolved secret in argv, but that
warning cannot prevent the operating system from briefly exposing the original
argv to other local observers.

Environment variables are safer than argv for many wrapped tools, but they are
not magic. Once Bywaf hands a secret to another process, that process is
responsible for not leaking it. If the wrapped tool prints `using token ...`,
`scanning subnet ...`, or echoes its effective configuration, Bywaf captures
that stdout/stderr as evidence of what happened. Plugin authors should read the
wrapped tool's documentation, test its verbose/debug/error modes, and avoid
passing sensitive values to tools that echo them.

## Plans

Commandlets that can describe risky work before running should implement
`plan()`. The framework strips `--plan` and `--yes`, calls the hook, audits the
report, and handles approval:

```python
from bywaf.plugin import PlanItem, PlanReport

def plan(self, context, args, input_events):
    targets = tuple(args)
    return PlanReport(
        action="scan-hosts",
        summary=f"Scan {len(targets)} targets",
        items=tuple(PlanItem("target", target) for target in targets),
        requires_confirmation=bool(context.vars.get_global("plan.required", "false")),
    )
```

Plan repairs can return patched arguments for this invocation only. The
framework records `plan.requested`, `policy.evaluated`, approval/denial, and
repair decisions, including `approved_by=<os user>`.

## Parsing Arguments

Use `argparse` inside `run()` when the command has real options:

```python
import argparse

parser = argparse.ArgumentParser(prog=self.spec.name)
parser.add_argument("name", nargs="?", default="world")
parser.add_argument("--uppercase", action="store_true")
parsed = parser.parse_args(args)
```

Bywaf catches `SystemExit` from argparse so `--help` works cleanly in the REPL.

## Rendering Tables

Plugins should hand structured table data to the framework instead of
manually padding strings. The same table can be rendered to the console now and
to Markdown, CSV, JSONL, HTML, DOCX, or XLSX later.

```python
from bywaf.rendering import Column, Table

context.render.table(
    Table.from_rows(
        (
            {"host": "127.0.0.1", "port": 22, "service": "ssh"},
            {"host": "127.0.0.1", "port": 80, "service": "http"},
        ),
        (
            Column("host", "Host"),
            Column("port", "Port", "right"),
            Column("service", "Service"),
        ),
        title="Open ports",
    )
)
```

For simple cases, `context.table(...)` is a compatibility wrapper:

```python
context.table(
    ({"host": "127.0.0.1", "port": 80},),
    ("host", "port"),
    title="Open ports",
)
```

The render request is audited as `framework.render.table.requested`, and the
frontend records `render.table` after it handles the request. Commandlets that
use table rendering should declare `framework.render.table`.

## Publishing Events

Yield dictionaries from `run()`:

```python
yield {"host": "127.0.0.1"}
```

The runner publishes each dictionary to the first topic in `spec.emits`.

```python
spec = CommandSpec(
    name="example",
    emits=("example.event",),
)
```

The event is stored with:

- `topic`
- `payload`
- `source`
- `pipeline_id`
- `command_run_id`
- `parent_command_run_id`
- timestamp

## Consuming Pipeline Input

The third argument to `run()` is `input_events`. In a pipeline, it contains
events from the previous pipeline step:

```python
def run(self, context, args, input_events):
    for event in input_events:
        host = event.payload.get("host")
        if host:
            yield {"host": host, "seen": True}
```

Declare consumed topics in `CommandSpec`:

```python
spec = CommandSpec(
    name="host_echo",
    consumes=("host.found",),
    emits=("host.echo",),
)
```

Then:

```text
bywaf> hostscanner 127.0.0.1 | host_echo
```

## Completion Specs

Plugins should describe completion behavior instead of relying on hard-coded
logic in the shell.

Use `ArgumentSpec` for positional arguments:

```python
from bywaf.plugin import ArgumentSpec, CompletionSpec

CommandSpec(
    name="readfile",
    arguments=(
        ArgumentSpec(
            "path",
            "file to read",
            completion=CompletionSpec("file"),
        ),
    ),
)
```

Optional positional arguments work too:

```python
ArgumentSpec(
    "path",
    "directory or file to list",
    required=False,
    completion=CompletionSpec("path"),
)
```

That is how the bundled `ls` commandlet supports both:

```text
bywaf> ls
bywaf> ls by<TAB>
```

Use `OptionSpec` for option value completion:

```python
from bywaf.plugin import OptionSpec

OptionSpec(
    "mode",
    "output mode",
    choices=("short", "long"),
    completion=CompletionSpec("choice", ("short", "long")),
)
```

Supported completion kinds:

```text
path        local paths
file        local files and paths
directory   local directories and paths
choice      fixed choices from CompletionSpec.values
topic       event topics
step        pipeline-step IDs (`step=` selector)
pipeline    pipeline IDs
job         job IDs
plugin      loaded commandlet names
none        no completion
```

Framework selectors use these same specs:

```text
--from-step
--from-pipeline
--from-topic
```

## Custom Completion

For commandlets that need special logic, implement a `complete()` method:

```python
from bywaf.plugin import CompletionContext


class PickTarget:
    spec = CommandSpec(
        name="pick_target",
        description="Pick a known target.",
    )

    def complete(
        self,
        context: CompletionContext,
        args: list[str],
        prefix: str,
    ):
        candidates = ["alpha", "beta", "gamma"]
        return [candidate for candidate in candidates if candidate.startswith(prefix)]

    def run(self, context, args, input_events):
        if args:
            yield {"target": args[0]}
```

The completion hook receives:

- `context.db`: the active event database, if available
- `context.varstore`: session variables for completion-time suggestions
- `args`: tokens already typed after the commandlet name
- `prefix`: the current token being completed

Return a list or any iterable of candidate strings.

## Runtime Context

At execution time, commandlets receive a `CommandContext`:

- `context.events`: mediated event publishing/query API for plugin code
- `context.db`: legacy/internal raw event database access, if available
- `context.vars`: scoped variables for the current commandlet
- `context.secrets`: resolve opaque secret references for credential use
- `context.pipeline_id`, `context.command_run_id`, `context.job_id`: step scope
- `context.parent_command_run_id`: upstream pipeline step, if any
- `context.note`: framework-level `note=` text for this pipeline step, if any
- `context.background`: whether the commandlet is running in the background
- `context.input_high_watermark`: highest upstream event ID already consumed
- `context.require_db()`: return the active DB or raise a clear error
- `context.require_foreground()`: reject background execution for unsafe actions
- `context.output(text)`: request normal console output from the framework
- `context.alert(message)`: request an operator alert from the framework
- `context.progress(...)`: report throttled structured progress
- `context.progress_started(...)`: report progress start
- `context.progress_completed(...)`: report progress completion
- `context.progress_failed(...)`: report progress failure
- `context.table(rows, columns)`: print small tabular command output
- `context.page_file(path)`: request frontend-owned paging for a local file
- `context.process.run(argv)`: run an external process and capture output
- `context.process.stream(argv)`: stream stdout/stderr chunks incrementally
- `context.artifacts.attach_file(path, name=..., note=...)`: attach one evidence file
- `context.artifacts.attach_files(paths)`: attach several evidence files
- `context.signals.pending(action=...)`: read live-control signals for this step
- `context.signals.applied(request, message, **details)`: acknowledge a signal
- `context.signals.ignored(request, message, **details)`: decline a signal
- `context.request(topic, payload)`: advanced escape hatch for framework requests
- `context.cancelled()`: whether a soft-cancellation request is pending
- `context.raise_if_cancelled()`: raise if cancellation is pending

For terminology, a pipeline groups one or more commandlet steps, a step is one
invocation of one commandlet, and a job supervises the foreground or background
work that executes those steps. Selectors and public plugin-facing APIs use
step terminology. Some persisted database columns still use historical names
such as `command_run_id`; plugin authors should treat those as storage details.
See `TERMINOLOGY.md` for the canonical definitions to use in docs, emitted
events, and user-facing messages.

Plugin-domain signals should be designed around steps. A step is the commandlet
execution context that can poll `context.signals`; a job is the framework's
supervised lifecycle wrapper, and a pipeline is a grouping scope rather than
code that can receive a plugin signal.

For beginner plugins, the core loop is usually:

```python
context.output("starting scan")
context.alert("discovered host 127.0.0.1")
context.progress(phase="scan", current=10, total=100, unit="hosts")
context.page_file("report.txt")
yield {"host": "127.0.0.1", "status": "up"}
```

Those helpers keep plugin code simple while still routing display and audit
state through the framework-owned event bus.

Commandlets do not need to parse `note=`. It is a framework-level selector that
the runner strips before calling plugin `run()`. The framework records the note
as `note.attached` with the current job, pipeline, and step IDs. Users
can review those notes with `note step=<id>`, `note pipeline=<id>`, or
`note job=<id> file=notes.txt`. Users can add post-hoc notes with
`note add step=<id> text=...`; notes are append-only events.

Commandlets also do not need to implement at-file expansion. The framework
expands `@file`, `@raw:file`, `@lines:file`, and `@@literal` before calling
plugin `run()`. Use `@lines:file` when a file should become multiple arguments,
such as a target list for a scanner. The framework also stores expanded input
files as provenance artifacts when artifact storage is available.

Commandlets also do not need to expand `$variables`. The framework expands
unquoted and double-quoted variables before plugin parsing, leaves
single-quoted variables literal, and audits expansion as
`framework.variable.expanded`.

Plugins that produce evidence files should attach them through
`context.artifacts` instead of leaving them as loose plaintext files:

```python
snapshot = context.artifacts.attach_file("snapshot.html", name="Landing page", note="initial capture")
context.output(f"attached artifact {snapshot.id}")

context.artifacts.attach_files(["snapshot.html", "headers.txt"])
```

Artifact bodies are stored in a separate artifact database paired with the main
event database. If the main DB is encrypted, the artifact DB is encrypted with
the same session passphrase; if the main DB is plaintext, the artifact DB is
plaintext too. The main event database records `artifact.attached` provenance
events containing the artifact id, hash, name, note, timestamp, job, pipeline,
and step IDs. A commandlet can attach multiple artifacts to the same step;
that is the expected model for screenshots, raw responses, parsed reports, and
notes produced by one action.

Users can later `artifact replace`, `artifact remove`, `artifact export`, or
`artifact verify` those records. Those mutations are audited in the main event
database while artifact bodies remain in the paired artifact store.

Use structured progress events for in-flight status. Progress is for UI/runtime
state; findings are still durable evidence events such as `host.found` or
`port.open`.

```python
context.progress_started(phase="tcp_scan", total=1000, unit="ports")

for index, port in enumerate(ports, start=1):
    context.progress(
        phase="tcp_scan",
        current=index,
        total=len(ports),
        unit="ports",
        target=host,
        message="Scanning TCP ports",
    )

context.progress_completed(phase="tcp_scan", current=len(ports), total=len(ports), unit="ports")
```

The framework emits `plugin.progress.started`, `plugin.progress.updated`,
`plugin.progress.completed`, and `plugin.progress.failed` events. `started`,
`completed`, and `failed` always emit. `updated` is throttled by the framework
unless the phase changes, enough time has passed, or the percent changed enough.
Users configure that policy with:

```text
set global.progress.min-interval-ms=250
set global.progress.min-percent-delta=1
```

Use `context.signals` for live-control requests that the framework delivers to
running commandlets:

```python
for request in context.signals.pending(action="prune"):
    targets = request.payload["args"].get("targets") or request.payload["args"].get("target")
    pruned = queue.prune(targets)
    context.signals.applied(request, "pruned pending targets", count=pruned)
```

The framework records the original `runtime.signal.requested` event. The
commandlet records whether it applied or ignored the request. Plugin-specific
actions such as `prune`, `mute`, and `verbosity` are cooperative; the plugin
decides what they mean for its own work queue and output policy.

Use `context.events` instead of raw `context.db` for event-bus work:

```python
for event in context.events.fetch(("host.found",), after_id=context.input_high_watermark):
    context.events.publish("example.seen_host", {"host": event.payload["host"]})
```

`context.events` records `db.read:<topic>` and `db.write:<topic>` capability
usage. Raw `context.db` remains available for privileged/internal framework
commandlets during the transition; accessing it records `db.raw`, and
third-party plugins should avoid it.

Finite listener commandlets should use `context.events.follow(...)` instead of
hand-rolled polling loops. In a normal pipeline, a downstream listener should
stop after its parent step has completed or failed and all matching events have
been drained:

```python
for event in context.events.follow(
    ("host.found",),
    after_id=context.input_high_watermark,
    until_parent_done=True,
):
    context.events.publish("example.seen_host", {"host": event.payload["host"]})
```

### Trigger Providers

Long-running service plugins should leave `until_parent_done` false and use
`context.cancelled()`, `context.signals`, or their own configured stop
condition. The bundled `watchdog` commandlet is the current service-plugin
example: it is marked `service = true`, provides a trigger rule through its
plugin API, and loops until the framework requests cancellation during
shutdown. The trigger rule is provider-owned, not user-authored:

```text
ON plugin.capability.used capability=network.connect job_id=<active job>
DO watchdog --session-service
```

Trigger providers should expose rules through plugin API calls so users do not
define framework triggers directly. A trigger rule should name the event topic
it observes, the exact condition it matches, and the framework action command
it starts. Rules can use narrow built-in predicates such as a required
capability, payload equality checks, active-job matching, excluded commandlets,
and self-trigger suppression. Rules also declare an action mode:
`foreground`, `background`, or `service`.

Trigger rules must also be declared in the provider sidecar manifest with
`[[triggers]]`. Bywaf compares manifest trigger metadata against the plugin's
`triggers()` output before exposing the provider. This keeps catalog builds
pre-import: release tooling can describe trigger behavior from
`bywaf.plugin.toml` without executing plugin code.

Trigger names are provider-local. The framework derives the durable trigger
identity from the provider entry and local trigger name, such as
`runtime.watchdog.network-access-starts-watchdog`. Cursors, fired-event
tracking, and lifecycle audit events use that provider-scoped identity, while
audit payloads also include the local `name` and `provider` separately.

The plugin module exposes trigger rules with a module-level `triggers()`
function. The returned `TriggerSpec` objects are code-level provider metadata;
they are not commands a user writes into the REPL:

```python
from bywaf.plugin import TriggerSpec


def triggers() -> tuple[TriggerSpec, ...]:
    return (
        TriggerSpec(
            name="network-access-starts-watchdog",
            topic="plugin.capability.used",
            action_command="watchdog --session-service",
            description="ON network.connect capability use by an active job DO start the session watchdog",
            action_mode="service",
            capability="network.connect",
            active_job=True,
            exclude_commandlets=("watchdog",),
            suppress_self_trigger=True,
        ),
    )
```

The sidecar manifest must declare the same trigger metadata so tooling can
inspect the provider before importing plugin code:

```toml
[[triggers]]
name = "network-access-starts-watchdog"
topic = "plugin.capability.used"
action_command = "watchdog --session-service"
action_mode = "service"
description = "ON network.connect capability use by an active job DO start the session watchdog"
capability = "network.connect"
active_job = true
exclude_commandlets = ["watchdog"]
suppress_self_trigger = true
```

Bywaf emits `framework.trigger.enabled` when a trigger rule becomes active,
`framework.trigger.fired` when an event matches the rule, and
`framework.trigger.disabled` when the session disables the rule. Fired events
include the source event ID so auditors can trace what caused the action.
Trigger evaluation uses per-trigger cursors so each rule only inspects events
newer than its last high-water mark.

### Process Execution

Plugins should avoid direct process execution with `subprocess`,
`os.system`, or `os.spawn*`. External tool wrappers should declare
`process.run`, go through `context.process`, and let Bywaf record the request
and outcome for auditability.

For short commands, use the blocking API:

```python
result = context.process.run(["tool", "--json"], timeout=30)
if result.ok:
    context.output(result.stdout)
```

For long-running commands whose output arrives over time, use the streaming API:

```python
for chunk in context.process.stream(["tool", "--verbose"]):
    if chunk.stream == "stdout":
        context.output(chunk.text, end="")
```

The blocking API records `framework.process.run.requested` and `process.run`.
The streaming API records `framework.process.stream.requested`,
`process.started`, `process.stdout`, `process.stderr`, and `process.exited`.

Use `require_db()` and `require_foreground()` instead of hand-writing common
guards:

```python
db = context.require_db()
context.require_foreground()
```

Those calls produce consistent errors such as `job requires an active database`
or `job must run in the foreground`. Pass a label when a submode needs a more
specific message:

```python
db = context.require_db("portscanner --listen")
```

Plugin variables are scoped. If `http_probe` calls:

```python
context.vars.get("cookie-file")
```

the framework reads:

```text
http/http_probe.cookie-file
```

Plugins cannot enumerate or directly read another plugin's variables through
`context.vars`. Global variables are explicit:

```python
context.vars.get_global("proxy")
```

which reads:

```text
global.proxy
```

Users can invoke a commandlet by its registered `@commandlet(name=...)` value,
or by a provider-qualified catalog alias such as `http/http_probe`. A provider
package may expose more than one commandlet; the qualified form keeps the catalog
path visible without changing the commandlet's canonical runtime identity.

Plugin code declares what it provides: commandlets, metadata, options,
capabilities, emitted topics, and behavior. It does not get to choose where it
lives in the global catalog. The loader, filesystem discovery context, or a
trusted signed catalog decides the provider/catalog path. If local development
loading later supports a `path=` override, that placement is an operator/loader
choice, not a value trusted from plugin code.

### Catalog Variable Keys

A catalog variable key is a stable user-settable variable name attached to a
commandlet catalog path:

```text
<catalog/path/to/commandlet>.<variable-name>
```

The slash-delimited prefix is the commandlet catalog path. The dotted suffix is
the variable name. For example, `set http/http_probe.timeout=3` stores the
`timeout` value for the `http_probe` commandlet. `use http_probe` or
`use http/http_probe` lets the user write `set timeout=3` as shorthand for the
same scoped variable.

Catalog variable keys are stable before and after plugin import. If a user sets
`set http/repo_exposure/git_expose_check.timeout=10` before that commandlet is
loaded, Bywaf stores that exact key and warns that the commandlet is not loaded
yet. When the plugin later loads and binds to
`http/repo_exposure/git_expose_check`, the key is reused as-is. Plugin defaults
only fill missing keys; they do not overwrite a value the user set earlier.

Commandlet variables are the normal durable configuration surface for plugin
behavior. Invocation arguments override commandlet variables for that one
execution, and code defaults are the fallback:

```text
http/repo_exposure/git_expose_check target=https://example.com timeout=2
```

uses `timeout=2` for that invocation even if the stored catalog variable is:

```text
http/repo_exposure/git_expose_check.timeout=10
```

Provider-scoped variables are separate and should be rare. Use them only for
configuration that is intentionally shared by multiple commandlets from the same
provider:

```text
set http/repo_exposure.proxy=http://127.0.0.1:8080
```

Commandlets must opt into provider-scoped reads explicitly. The short form reads
the immediate provider that owns the commandlet:

```python
proxy = context.vars.get_provider("proxy")
```

Provider reads must also be declared in both Python commandlet metadata and
`bywaf.plugin.toml`. Undeclared provider-variable reads fail instead of falling
back to raw variable keys:

```python
@commandlet(
    name="check",
    description="Example provider variable use.",
    capabilities=("network.connect",),
    provider_variables=("proxy",),
)
class Check(CommandletBase):
    ...
```

```toml
[[commandlets]]
name = "check"
capabilities = ["network.connect"]
provider_variables = ["proxy"]
```

Provider variables are limited to the immediate provider in the public plugin
API. A commandlet at `cloud/aws/s3/public_bucket/check` can read variables at
`cloud/aws/s3/public_bucket`, but it cannot directly read `cloud/aws` variables
through `context.vars`.

```text
set cloud/aws/s3/public_bucket.proxy=http://127.0.0.1:8080
```

```python
proxy = context.vars.get_provider("proxy")
```

A portable plugin should not assume its final catalog path unless it is bundled
or loaded from a trusted catalog that fixes that path. Use commandlet-local
variables for portable plugins. Provider-scoped variables are appropriate for
bundled or catalog-pinned plugin families where the immediate provider path is
stable. Broader ancestor-provider access may be added later with manifest
permissions; do not emulate it by probing raw variable keys.

Do not rely on implicit fallback from commandlet variables to provider variables
or global variables. If a commandlet needs framework-global configuration, use
`context.vars.get_global("name")` deliberately and document why.

### Secrets

Secret variables are different. If an operator sets:

```text
bywaf> set --secret network/ssh_probe.password=client-password
```

ordinary `context.vars.get("password")` returns an opaque secret reference, not
the plaintext. A commandlet that declared `framework.secret.resolve` can resolve
that reference just before it calls the backing library:

```python
password_ref = context.vars.get("password")
password = context.secrets.resolve(password_ref, "")
```

`context.secrets.resolve()` passes through normal non-secret text, so the same
code works for explicit CLI values and redacted variable references. Resolving
a real secret reference emits a `plugin.capability.used` audit event for
`framework.secret.resolve`.

If a commandlet then passes that secret to a subprocess in argv, Bywaf redacts
the known secret in process audit events and emits a warning event. This is
still discouraged because the operating system may expose argv briefly through
process listings before Bywaf can audit anything:

```python
import sys

from bywaf.plugin import CommandletBase, commandlet, option

@commandlet(
    name="secret_demo",
    description="Demonstrate secret resolution and argv redaction.",
    usage="secret_demo",
    capabilities=(
        "framework.secret.resolve",
        "framework.secret.argv",
        "process.run",
    ),
)
@option("password", "demo password", secret=True)
class SecretDemo(CommandletBase):
    def run(self, context, args, input_events):
        del args, input_events
        password_ref = context.vars.get("password")
        password = context.secrets.resolve(password_ref, "")

        result = context.process.run(
            [
                sys.executable,
                "-c",
                "import sys; print('subprocess saw', sys.argv[1])",
                f"password={password}",
            ]
        )
        context.output(result.stdout, end="")
        return ()
```

With:

```text
bywaf> set --secret secret_demo.password=client-password
secret_demo.password=[REDACTED] fingerprint=hmac-sha256:7e3...
bywaf> secret_demo
subprocess saw password=client-password
```

the subprocess output is captured exactly because the child process really did
receive the secret:

```text
process.run {
  "argv": ["python3", "-c", "...", "password=[REDACTED]"],
  "stdout": "subprocess saw password=client-password\n",
  "stderr": "",
  "ok": true
}
```

Bywaf also records the argv leak warning:

```text
process.secret.argv {
  "argv": ["python3", "-c", "...", "password=[REDACTED]"],
  "secret_fingerprints": ["hmac-sha256:7e3..."]
}
```

The important distinction is that Bywaf can redact known secrets from its own
argv audit fields, but it does not rewrite subprocess stdout/stderr because
that output is evidence of what the tool actually produced. Plugin authors
should avoid argv secrets and should avoid printing secrets from child tools.
Use environment variables, stdin, or restrictive temporary files when the
wrapped tool supports them.

A better process-wrapped shape uses `env=` instead of argv:

```python
password_ref = context.vars.get("password")
password = context.secrets.resolve(password_ref, "")

result = context.process.run(
    ["example-tool", "--host", "target.example"],
    env={"EXAMPLE_TOOL_PASSWORD": password or ""},
)
```

In that case the audited process argv does not contain the secret:

```text
framework.process.run.requested {
  "argv": ["example-tool", "--host", "target.example"],
  "env": "<not recorded>"
}
```

Bywaf intentionally does not record the supplied environment map. However, if
`example-tool` prints the password, token, subnet, or other sensitive value,
that value still appears in captured `stdout`/`stderr`.

At launch time, Bywaf captures the effective commandlet and global variables
for each pipeline step and stores that snapshot in SQLite under its
step identity. During execution, `context.vars.get()` checks the step
snapshot first, then falls back to the session variable store. This lets two
background steps of the same commandlet
keep different values even if the operator changes session variables after the
first job starts. It also means `event step=<id>` can report the variables that
were actually supplied to that step.

Plugins should treat interpreter behavior, such as the prompt, as framework
owned. A plugin running in a background process cannot directly call a method on
the parent REPL process. For cross-process requests, plugins should publish
events to the database and let the foreground interpreter decide whether to
apply them.

## Framework Requests and Audit Events

Plugins can request interpreter-owned actions by publishing structured request
events. The interpreter remains the authority: it validates the request, applies
it if allowed, and writes a follow-up event so the action is auditable.

For example, to request a prompt change:

```python
context.request(
    "shell.prompt.requested",
    {"prompt": "%u@%h %T > ", "reason": "operator context changed"},
)
```

When the foreground REPL processes the request, it records one of:

```text
shell.prompt.updated
framework.request.denied
```

This pattern is preferred over direct method calls because it works across
processes and leaves a database audit trail of what was requested and what the
interpreter did.

Normal commandlet execution is job-audited through the database. Foreground
commandlets run in-process but still record `job.requested`, `job.claimed`,
`job.started`, and `job.finished` or `job.failed`. Background jobs use the same
job lifecycle, but a worker process claims and runs the queued job. Long-running
commandlets should call `context.cancelled()` or `context.raise_if_cancelled()`
periodically so `job cancel <id>` can stop them cooperatively.

## Embedding Bywaf

Applications should use `BywafSession` as the public library entry point:

```python
from pathlib import Path
from bywaf import BywafSession

session = BywafSession.open(Path(".bywaf/bywaf.sqlite3"))
session.run("hostscanner 127.0.0.1")
for event in session.events(topic="host.found"):
    print(event.payload)
```

This is the preferred route for local GUIs, web frontends, and automation
because they can render jobs and events directly from the database-backed API.

## A Complete Example With Completion

This commandlet reads a file and emits one event containing its path and size:

```python
import argparse
from collections.abc import Iterable
from pathlib import Path

from bywaf.events import Event
from bywaf.plugin import (
    ArgumentSpec,
    CommandContext,
    CommandSpec,
    Commandlet,
    CompletionSpec,
)


class FileInfo:
    spec = CommandSpec(
        name="file_info",
        description="Emit metadata about a local file.",
        usage="file_info <path>",
        examples=("file_info README.md",),
        arguments=(
            ArgumentSpec("path", "file to inspect", completion=CompletionSpec("file")),
        ),
        emits=("file.info",),
    )

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        parser = argparse.ArgumentParser(prog=self.spec.name)
        parser.add_argument("path")
        parsed = parser.parse_args(args)

        path = Path(parsed.path)
        stat = path.stat()
        yield {
            "path": str(path),
            "size": stat.st_size,
            "is_dir": path.is_dir(),
        }


def plugin() -> Commandlet:
    return FileInfo()
```

Install it:

```text
.bywaf/plugins/file_info/plugin.py
```

Use it:

```text
bywaf> plugin load=file_info --force
loaded file_info
bywaf> file_info READ<TAB>
bywaf> file_info README.md
1: file.info {'path': 'README.md', 'size': 12345, 'is_dir': False}
```

## Plugin Defaults

A plugin module can define `DEFAULTS`:

```python
DEFAULTS = {
    "timeout": 5,
}
```

When the plugin loads, Bywaf stores those values using the commandlet name as a
prefix:

```text
file_info.timeout=5
```

Users can override values:

```text
bywaf> set file_info.timeout=10
```

Use `CommandletBase.var_default()` when an argparse option should use a
commandlet variable as its default:

```python
parser.add_argument(
    "--timeout",
    type=float,
    default=self.var_default(context, "timeout", 5, cast=float),
)
```

This keeps precedence consistent: explicit CLI argument, then commandlet
variable, then code default. Invalid variable values raise a clear `ValueError`
before the commandlet does any work.

For positional arguments that may come from a variable, use
`CommandletBase.values_or_var()`:

```python
parser.add_argument("targets", nargs="*")
parsed = parser.parse_args(args)
targets = self.values_or_var(context, parsed.targets, "targets", required=True)
```

That lets `file_info README.md` override `file_info.targets`, while `file_info`
can fall back to `file_info.targets` if the user configured it.
