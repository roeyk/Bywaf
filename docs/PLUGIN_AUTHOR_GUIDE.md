# Writing Bywaf Plugins

This guide shows how to write a small Bywaf plugin and how to make it pleasant
to use from the interactive shell.

Bywaf plugins provide commandlets. A commandlet is a small class with:

- a `CommandSpec`, which describes the commandlet
- a `run()` method, which performs the work
- a `plugin()` factory function, which returns the commandlet instance

Commandlets can publish events by yielding dictionaries. The runner inserts
those dictionaries into SQLite under the first topic listed in `spec.emits`.

## Guide Index

- [Plugin Types](#plugin-types)
- [Plugin Manifest](#plugin-manifest)
- [Manifest Generation And Inspection](#manifest-generation-and-inspection)
- [Current API, Not Generic Plugin Patterns](#current-api-not-generic-plugin-patterns)
- [Defining Inputs: Arguments vs Options](#defining-inputs-arguments-vs-options)
- [A Minimal Commandlet](#a-minimal-commandlet)
- [Complete External Plugin Example](#complete-external-plugin-example)
- [CommandSpec Fields](#commandspec-fields)
- [Plans](#plans)
- [Parsing Arguments](#parsing-arguments)
- [Rendering Tables](#rendering-tables)
- [Publishing Events](#publishing-events)
- [Consuming Pipeline Input](#consuming-pipeline-input)
- [Completion Specs](#completion-specs)
- [Custom Completion](#custom-completion)
- [Runtime Context](#runtime-context)
- [Framework Requests and Audit Events](#framework-requests-and-audit-events)
- [Trigger Providers](#trigger-providers)
- [Process Execution](#process-execution)
- [Secrets](#secrets)
- [Embedding Bywaf](#embedding-bywaf)
- [A Complete Example With Completion](#a-complete-example-with-completion)
- [Plugin Defaults](#plugin-defaults)
- [Loading and Packaging Plugins](#loading-and-packaging-plugins)
- [Standalone Plugin Checking](#standalone-plugin-checking)
- [Plugin Catalog Signing](#plugin-catalog-signing)
- [Testing a Plugin](#testing-a-plugin)
- [Practical Guidelines](#practical-guidelines)

# Plugin Types

Bywaf plugins can be described along two separate axes: how they integrate with
other code, and what role they play in a workflow. Keeping those separate makes
capabilities, dependencies, and failure behavior easier to reason about.

Common integration types:

- **Native plugins** use Bywaf APIs plus Python standard-library code. This is
  the default case when a plugin is neither library-backed nor process-wrapped.
  These are the easiest to audit and package. Examples include filters,
  correlation commandlets, and simple renderers.
- **Library-backed plugins** call a third-party Python package or non-Bywaf
  Python library in-process, such as an HTTP client, Scapy, dnspython, or an
  nmap binding. Normal imports from Bywaf itself or sibling bundled plugins do
  not make a plugin library-backed. These plugins can expose richer objects
  than command-line tools, but failures happen inside the Bywaf process.
- **Process-wrapped plugins** run a mature external program through
  `context.process.run()` or `context.process.stream()`. They should declare
  `process.run` and let the framework capture stdout, stderr, return codes, and
  audit events.
- **Native or FFI plugins** load compiled code or talk to a native component.
  Treat these as higher-risk because crashes, ABI mismatches, or memory-safety
  bugs can affect the framework process unless they are isolated.

Common workflow roles:

- **Scanner** commandlets discover hosts, ports, services, or findings.
- **Listener** commandlets watch event streams and react to new data.
- **Renderer/exporter** commandlets turn normalized events into tables, charts,
  documents, or handoff files.
- **Correlator/analyzer** commandlets combine prior events into new conclusions.
- **Runtime/storage** commandlets manage jobs, pipelines, audit logs, notes, or
  artifacts, or databases.

These traits are intentionally orthogonal. A plugin can be both library-backed
and process-wrapped if it uses a third-party Python package and also invokes an
external tool. A long-running service plugin is also a separate lifecycle trait
from whether it is native, library-backed, or process-wrapped.

See `CAPABILITY_MODEL.md` for how these integration types affect trust
boundaries, failure semantics, deployment, and capability declarations.

# Plugin Manifest

Filesystem plugins may include `bywaf.plugin.toml` next to `plugin.py`.
Bundled plugins use sidecar manifests such as `nikto.plugin.toml` next to
`nikto.py`. When present, the manifest is authoritative: Bywaf registers only
the commandlets listed in `[[commandlets]]`. Extra commandlets returned by
`plugin()` or `plugins()` are ignored, and commandlets declared in the manifest
but missing from Python code cause plugin loading to fail.

See `MANIFEST_SPECIFICATION.md` for the complete sidecar TOML schema and
validation rules.

```toml
[plugin]
library_backed = true
process_wrapped = true
service = false
roles = ["command-provider"]

[[commandlets]]
name = "example"
capabilities = ["network.connect"]
secret_options = ["password"]
```

Implementation traits are independent:

- `native` is the default when neither `library_backed` nor `process_wrapped`
  is true;
- `library_backed` means the plugin uses a third-party Python package or
  non-Bywaf Python library;
- `process_wrapped` means the plugin invokes an external executable through the
  framework process API. The external process may be a compiled binary, script,
  package entrypoint, or other executable tool;
- `service` means the plugin is expected to run long-lived or continuously.

Each `[[commandlets]]` entry should also list the commandlet capabilities and
any secret options. For now Bywaf requires manifest `capabilities` to match
`CommandSpec.capabilities` exactly and manifest `secret_options` to match
Python `OptionSpec.secret` metadata exactly. This is a pre-load consistency
check, not the only enforcement layer: runtime policy still audits and can deny
actual framework API use if a plugin attempts behavior outside its declared
capabilities.

# Manifest Generation And Inspection

Generate a starter manifest from an existing plugin with:

```text
bywaf-plugin-manifest path/to/plugin.py
bywaf-plugin-manifest --library-backed path/to/plugin.py -o bywaf.plugin.toml
```

The generator uses runtime inspection. It imports the plugin module, loads
commandlets and triggers, and writes the metadata that Bywaf sees at runtime.
Use it for your own development tree or reviewed code. It is a convenience
tool, not a substitute for manifest review.

`--infer-capabilities` adds a static AST analysis pass. That pass looks for
recognizable framework calls and direct Python APIs that imply capabilities.
It does not parse the whole plugin API from decorators, and it is not a proof
that the plugin cannot do anything else.

Keep these boundaries clear:

| Question | Source of truth |
| --- | --- |
| What commandlets and triggers does the manifest generator emit? | Runtime inspection of loaded plugin specs. |
| What likely capabilities did the source code use? | Optional AST hints from `--infer-capabilities`. |
| What commandlets, capabilities, secret options, and triggers may load? | `bywaf.plugin.toml` or bundled `*.plugin.toml`. |
| How does a commandlet parse runtime args? | Python `run()` method using `self.parser()`. |
| Does the manifest sandbox plugin code? | No. It records trust metadata and consistency expectations. |

# Current API, Not Generic Plugin Patterns

Bywaf's current plugin API is decorator-driven and stream-oriented. Do not copy
generic Python plugin examples that manage a session object, imperatively add
arguments in `__init__`, or manually emit custom event objects. Those patterns
look plausible, but they are not the Bywaf API.

Use this API:

| Task | Current Bywaf API |
| --- | --- |
| Base class | `CommandletBase` |
| Metadata | `@commandlet(...)` |
| Positional metadata | `@argument(...)` |
| Option metadata | `@option(...)` |
| Runtime entry point | `run(self, context: CommandContext, args: list[str], input_events: Iterable[Event])` |
| Normal event emission | `yield {...}` |
| Direct event-bus access | `context.events.publish(...)` only when direct event access is needed |
| Console output | `context.output(...)` |
| Operator alert | `context.alert(...)` |
| Factory | `def plugin() -> Commandlet: return YourCommandlet()` |

Do not use these generic or legacy-looking patterns:

| Do not use | Use instead |
| --- | --- |
| `BaseCommandlet` | `CommandletBase` |
| `CommandletType.NATIVE` | Manifest traits and `@commandlet(...)` metadata |
| `BaseEvent` | `Event` for input rows; yielded dictionaries for normal output |
| `self.add_argument(...)` | `@argument(...)` / `@option(...)` metadata plus `self.parser()` in `run()` |
| `self.emit_event(...)` | `yield {...}` for normal commandlet output |
| `self.log_info(...)` / `self.log_warning(...)` | `context.output(...)`, `context.alert(...)`, or structured events |
| `self.session` | `context` |
| `run(self, target, args)` | `run(self, context, args, input_events)` |
| Class attributes `consumes = [...]` / `produces = [...]` | `@commandlet(consumes=(...), emits=(...))` |

Here is the smallest decorator-based skeleton:

```python
from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, argument, commandlet


@commandlet(
    name="hello",
    description="Say hello and emit a greeting event.",
    usage="hello [name]",
    examples=("hello", "hello world"),
    emits=("hello.greeting",),
    capabilities=("framework.console.output",),
)
@argument("name", "name to greet", required=False)
class Hello(CommandletBase):
    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        parser = self.parser()
        parser.add_argument("name", nargs="?", default="world")
        parsed = parser.parse_args(args)
        context.output(f"hello, {parsed.name}")
        yield {"name": parsed.name, "message": f"hello, {parsed.name}"}


def plugin() -> Commandlet:
    return Hello()
```

Decorator metadata drives help, completion, manifests, and future introspection.
The `argparse` parser inside `run()` still validates the actual command-line
arguments at execution time. Keep the metadata and parser behavior aligned.

# Defining Inputs: Arguments vs Options

Bywaf splits command input metadata into positional arguments and named options.
The distinction follows what the operator types:

| User input shape | Decorator | Example |
| --- | --- | --- |
| Positional value | `@argument(...)` | `cat README.md` |
| Optional positional value | `@argument(..., required=False)` | `hello` or `hello world` |
| Named flag or setting | `@option(...)` | `portscanner --ports 22,80,443` |
| Secret named setting | `@option(..., secret=True)` | `ssh_probe --password ...` |

Use `@argument` for values the user supplies by position:

```python
@argument("path", "file to print", completion="file")
@argument("target", "host, address range, or CIDR")
```

Use `@option` for values the user supplies by name, usually as `--name`:

```python
@option("port", "target port", default="443")
@option("timeout", "timeout seconds", default="5")
@option("password", "SSH password", secret=True)
```

Do not write option flags as arguments:

| Wrong | Right |
| --- | --- |
| `@argument("--port", "target port")` | `@option("port", "target port", default="443")` |
| `@argument("--timeout", "timeout")` | `@option("timeout", "timeout seconds", default="5")` |

The decorators describe the public commandlet contract. They drive help,
completion, manifest generation, plugin checking, and capability review. They
do not replace runtime parsing. Inside `run()`, build the actual parser with
`self.parser()` and keep it consistent with the decorator metadata:

```python
from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option


@commandlet(
    name="port_knocker",
    description="Check one configured port on incoming hosts.",
    consumes=("host.found",),
    emits=("service.discovered",),
    capabilities=("framework.console.alert", "network.connect"),
)
@option("port", "target port to check", default="443")
class PortKnocker(CommandletBase):
    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        parser = self.parser()
        parser.add_argument("--port", default=self.var_default(context, "port", "443"))
        parsed = parser.parse_args(args)

        for event in input_events:
            host = event.payload.get("host")
            if not host:
                continue

            context.alert(f"Checking port {parsed.port} on {host}")
            yield {"host": host, "port": parsed.port, "status": "checked"}


def plugin() -> Commandlet:
    return PortKnocker()
```

# A Minimal Commandlet

Create a plugin directory:

```text
.bywaf/plugins/hello/
  plugin.py
  bywaf.plugin.toml
```

Put this in `.bywaf/plugins/hello/plugin.py`:

```python
from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, argument, commandlet


@commandlet(
    name="hello",
    description="Say hello and emit a greeting event.",
    usage="hello [name]",
    examples=("hello", "hello world"),
    emits=("hello.greeting",),
    capabilities=("framework.console.output",),
)
@argument("name", "name to greet", required=False)
class Hello(CommandletBase):
    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        del input_events
        parser = self.parser()
        parser.add_argument("name", nargs="?", default="world")
        parsed = parser.parse_args(args)
        message = f"hello, {parsed.name}"
        context.output(message)
        yield {"name": parsed.name, "message": message}


def plugin() -> Commandlet:
    return Hello()
```

Put this in `.bywaf/plugins/hello/bywaf.plugin.toml`:

```toml
[plugin]
native = true

[[commandlets]]
name = "hello"
capabilities = [
  "framework.console.output",
]
```

Load and run it:

```text
bywaf> load --force plugin=hello
loaded hello
bywaf> hello world
hello, world
1: hello.greeting {'name': 'world', 'message': 'hello, world'}
```

Show the events:

```text
bywaf> event hello.greeting
```

# Complete External Plugin Example

This example shows a complete filesystem plugin package with both `plugin.py`
and `bywaf.plugin.toml`. It checks common HTTP security headers and emits one
structured event. It uses only the Python standard library, so
`library_backed = false` is correct. If you replace the HTTP code with a
third-party package such as `requests`, mark the manifest as
`library_backed = true` and document that dependency.

Create this package:

```text
.bywaf/plugins/http_header_check/
  plugin.py
  bywaf.plugin.toml
```

Put this in `.bywaf/plugins/http_header_check/bywaf.plugin.toml`:

```toml
[plugin]
native = true
library_backed = false
process_wrapped = false
service = false
roles = ["command-provider"]

[[commandlets]]
name = "http_header_check"
capabilities = [
  "network.connect",
  "framework.console.output",
  "framework.console.alert",
]
```

Put this in `.bywaf/plugins/http_header_check/plugin.py`:

```python
from collections.abc import Iterable
import http.client
import urllib.parse

from bywaf.events import Event
from bywaf.plugin import (
    CommandContext,
    Commandlet,
    CommandletBase,
    argument,
    commandlet,
)


@commandlet(
    name="http_header_check",
    description="Check common HTTP security headers on a target URL.",
    usage="http_header_check <url>",
    examples=(
        "http_header_check https://example.com",
        "http_header_check https://google.com",
    ),
    emits=("http.headers.checked",),
    capabilities=(
        "network.connect",
        "framework.console.output",
        "framework.console.alert",
    ),
)
@argument("url", "Target URL to check", required=True)
class HttpHeaderCheck(CommandletBase):
    """Check common security headers using only the standard library."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        del input_events

        parser = self.parser()
        parser.add_argument("url", help="Target URL to check")
        parsed = parser.parse_args(args)

        url = parsed.url
        context.output(f"Checking security headers for: {url}")

        try:
            parsed_url = urllib.parse.urlparse(url)
            if not parsed_url.scheme:
                parsed_url = urllib.parse.urlparse(f"https://{url}")

            scheme = parsed_url.scheme.lower()
            hostname = parsed_url.hostname
            port = parsed_url.port

            if hostname is None:
                context.alert("Invalid URL: no hostname found")
                return
            if scheme not in {"http", "https"}:
                context.alert("Invalid URL: scheme must be http or https")
                return

            if scheme == "https":
                conn = http.client.HTTPSConnection(hostname, port, timeout=10)
            else:
                conn = http.client.HTTPConnection(hostname, port, timeout=10)

            try:
                path = urllib.parse.urlunparse(
                    ("", "", parsed_url.path or "/", "", parsed_url.query, "")
                )
                conn.request("GET", path)
                resp = conn.getresponse()

                security_headers = {
                    "Strict-Transport-Security": resp.getheader("strict-transport-security"),
                    "X-Frame-Options": resp.getheader("x-frame-options"),
                    "X-Content-Type-Options": resp.getheader("x-content-type-options"),
                    "X-XSS-Protection": resp.getheader("x-xss-protection"),
                    "Content-Security-Policy": resp.getheader("content-security-policy"),
                    "Referrer-Policy": resp.getheader("referrer-policy"),
                    "Permissions-Policy": resp.getheader("permissions-policy"),
                }
                missing = [key for key, value in security_headers.items() if not value]
                score = max(0, 100 - len(missing) * 15)

                context.output(f"Status: {resp.status} | Security Score: {score}/100")
                if missing:
                    context.alert(f"Missing security headers: {', '.join(missing)}")
                else:
                    context.output("All major security headers present.")

                yield {
                    "url": url,
                    "status_code": resp.status,
                    "headers": security_headers,
                    "missing_headers": missing,
                    "security_score": score,
                }
            finally:
                conn.close()

        except (OSError, http.client.HTTPException, ValueError) as exc:
            context.alert(f"Request failed: {exc}")
            yield {
                "url": url,
                "error": str(exc),
                "status": "failed",
            }


def plugin() -> Commandlet:
    return HttpHeaderCheck()
```

Load it, run it, and inspect emitted events:

```text
bywaf> load --force plugin=http_header_check
bywaf> http_header_check https://example.com
bywaf> event http.headers.checked
```

# CommandSpec Fields

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

Operators can also set any variable as a secret with `var --secret name=value`.
Bywaf does not guess based on variable names; plain `var password=value` is an
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

# Plans

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

# Parsing Arguments

Use `argparse` inside `run()` when the command has real options:

```python
import argparse

parser = argparse.ArgumentParser(prog=self.spec.name)
parser.add_argument("name", nargs="?", default="world")
parser.add_argument("--uppercase", action="store_true")
parsed = parser.parse_args(args)
```

Bywaf catches `SystemExit` from argparse so `--help` works cleanly in the REPL.

# Rendering Tables

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

# Publishing Events

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

# Consuming Pipeline Input

The third argument to `run()` is `input_events`. In a pipeline, it contains
events from the previous stage:

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

# Completion Specs

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
run         command run IDs
pipeline    pipeline IDs
job         job IDs
plugin      loaded commandlet names
none        no completion
```

Framework selectors use these same specs:

```text
--from-run
--from-pipeline
--from-topic
```

# Custom Completion

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

# Runtime Context

At execution time, commandlets receive a `CommandContext`:

- `context.events`: mediated event publishing/query API for plugin code
- `context.db`: legacy/internal raw event database access, if available
- `context.vars`: scoped variables for the current commandlet
- `context.secrets`: resolve opaque secret references for credential use
- `context.pipeline_id`, `context.command_run_id`, `context.job_id`: run scope
- `context.parent_command_run_id`: upstream pipeline stage, if any
- `context.note`: framework-level `note=` text for this command run, if any
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
- `context.signals.pending(action=...)`: read live-control signals for this run
- `context.signals.applied(request, message, **details)`: acknowledge a signal
- `context.signals.ignored(request, message, **details)`: decline a signal
- `context.request(topic, payload)`: advanced escape hatch for framework requests
- `context.cancelled()`: whether a soft-cancellation request is pending
- `context.raise_if_cancelled()`: raise if cancellation is pending

For terminology, a pipeline groups one or more commandlet runs, a run is one
invocation of one commandlet, and a job supervises the foreground or background
work that executes those runs. See `TERMINOLOGY.md` for the canonical
definitions plugin authors should use in docs, emitted events, and user-facing
messages.

Plugin-domain signals should be designed around runs. A run is the commandlet
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
as `note.attached` with the current job, pipeline, and command-run IDs. Users
can review those notes with `note run=<id>`, `note pipeline=<id>`, or
`note job=<id> file=notes.txt`. Users can add post-hoc notes with
`note add run=<id> text=...`; notes are append-only events.

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
and command-run IDs. A commandlet can attach multiple artifacts to the same run;
that is the expected model for screenshots, raw responses, parsed reports, and
notes produced by one action.

Users can later `artifact replace`, `artifact remove`, `artifact save`, or
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
var global.progress.min-interval-ms=250
var global.progress.min-percent-delta=1
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
hand-rolled polling loops. In a normal pipeline, a second-stage listener should
stop after its parent run has completed or failed and all matching events have
been drained:

```python
for event in context.events.follow(
    ("host.found",),
    after_id=context.input_high_watermark,
    until_parent_done=True,
):
    context.events.publish("example.seen_host", {"host": event.payload["host"]})
```

## Trigger Providers

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

## Process Execution

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
http_probe.cookie-file
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

## Secrets

Secret variables are different. If an operator sets:

```text
bywaf> var --secret ssh_probe.password=client-password
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
bywaf> var --secret secret_demo.password=client-password
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
for each `command_run_id` and stores that snapshot in SQLite. During execution,
`context.vars.get()` checks the run snapshot first, then falls back to the
session variable store. This lets two background runs of the same commandlet
keep different values even if the operator changes session variables after the
first job starts. It also means `event run=<id>` can report the variables that
were actually supplied to that run.

Plugins should treat interpreter behavior, such as the prompt, as framework
owned. A plugin running in a background process cannot directly call a method on
the parent REPL process. For cross-process requests, plugins should publish
events to the database and let the foreground interpreter decide whether to
apply them.

# Framework Requests and Audit Events

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

# Embedding Bywaf

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

# A Complete Example With Completion

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
bywaf> load --force plugin=file_info
loaded file_info
bywaf> file_info READ<TAB>
bywaf> file_info README.md
1: file.info {'path': 'README.md', 'size': 12345, 'is_dir': False}
```

# Plugin Defaults

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
bywaf> var file_info.timeout=10
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

# Loading and Packaging Plugins

During development, plain plugin names resolve under:

```text
.bywaf/plugins
```

So:

```text
bywaf> load --force plugin=file_info
```

loads:

```text
.bywaf/plugins/file_info/plugin.py
```

Explicit paths also work:

```text
bywaf> load --force plugin=./scratch/file_info
bywaf> load --force plugin=~/bywaf-plugins/file_info
```

Filesystem plugin packages must include `plugin.py` and `bywaf.plugin.toml`.
The manifest is required so Bywaf has commandlet names, capabilities, secret
options, trigger rules, and plugin traits available as package metadata instead
of treating imports as discovery.

`--force` is required for REPL-loaded filesystem plugins unless a future
runtime catalog trust check verifies the plugin first. Filesystem plugins are
arbitrary local Python code, so forcing a load is an explicit operator
acknowledgement that every plugin trust check is being bypassed for reviewed
local code.

Startup plugin roots use the same policy. If you start Bywaf with
`--plugin-root` and `--plugin-config`, use `--allow-unsigned-plugins` for
unsigned development plugins:

```text
bywaf --plugin-root ~/.bywaf/plugins --plugin-config ~/.bywaf/plugins/plugins.toml --allow-unsigned-plugins
```

The plugin catalog builder uses the same filesystem entry layout as runtime
loading. A config entry such as `default_plugins = ["myplugin"]` describes
`~/.bywaf/plugins/myplugin/plugin.py` plus
`~/.bywaf/plugins/myplugin/bywaf.plugin.toml`.

For reviewed external plugin trees, build and sign a catalog, then provide the
catalog and trusted public key at startup. Runtime verification checks the
catalog signature and the `plugin.py` / `bywaf.plugin.toml` hashes before
loading code:

```text
bywaf --plugin-root ~/.bywaf/plugins \
  --plugin-config ~/.bywaf/plugins/plugins.toml \
  --plugin-catalog ~/.bywaf/plugins/plugin-catalog.signed.json \
  --plugin-catalog-key ~/.bywaf/plugins/plugin-catalog.pub.pem
```

Runtime catalog trust decisions are audited with
`plugin.catalog.verified`, `plugin.catalog.rejected`,
`plugin.catalog.entry.verified`, and `plugin.catalog.entry.rejected`.

Plugin manifest signatures sign a digest of canonical parsed values, not raw
TOML bytes. Comments, whitespace, and formatting can change freely without
disturbing the signature; changes to the actual declarative values change the
digest. Lists in framework-managed config are treated as unordered sets by
policy, including capability lists, commandlet rows, trigger rows, roles,
excluded commandlets, and key lists.

Manifest metadata uses strict TOML types. Strings must be strings, booleans
must be `true` or `false`, and string lists must contain only strings. Bywaf
rejects malformed trust metadata instead of converting values such as
`"false"` or `123` into plausible catalog entries.

`--allow-missing-plugin-keys` and `--allow-mismatched-plugin-keys` are narrower
developer bypasses for future signed external plugin catalogs when the trusted
verification key is absent or does not match the plugin signature.
`--plugin-manifest-key` supplies the trusted public key for signed
`bywaf.plugin.toml` files. `--allow-unsigned-plugin-manifests` is the narrow
development bypass for unsigned manifests. The legacy
`--force-plugins` startup flag is a hidden compatibility alias for
`--allow-untrusted-plugins`, a command-line argument that states the full
tradeoff directly: load the plugin even though Bywaf cannot verify its
signature, signing key, or key match.

Official Bywaf releases reserve `bywaf/keys/plugin-manifest.pub.pem` for the
framework public verification key. Only public keys belong in that package;
private manifest-signing keys are maintainer release material and must stay
outside the repository and built packages. Operators can use
`--plugin-manifest-key` to trust a different public key for local or
third-party plugin ecosystems.

Official manifest-signing keys rotate annually with a 60-day staggered
transition. Bywaf publishes the next public verification key before it is used
for signing, temporarily trusts both the current and next public keys during
the transition window, starts signing new manifests with the next private key
on the rotation date, re-signs official plugin manifests with that key for the
rotation release, and retires the old public key after the transition window.
Retired keys are no longer part of the official trusted key set for normal
annual rotation. Revocation is reserved for suspected compromise or emergency
distrust and removes the affected key from trust immediately.

Maintainer storage controls for private signing keys are recorded in
`KEY_MANAGEMENT.md`. In short: private keys stay encrypted, outside the
repository and package tree, with permissions no broader than `0600`; public
verification keys can be committed and packaged.

Bundled plugins live under `bywaf/plugins/` and are loaded from
`bywaf/plugins/plugins.toml`. To make a bundled commandlet load automatically,
add its dotted module path to `default_plugins` and add or update the matching
sidecar manifest, for example `bywaf/plugins/http/nikto.plugin.toml`.

# Standalone Plugin Checking

Development plugin validation is done outside the Bywaf interpreter. Use the
standalone checker before loading a filesystem plugin with development trust
bypasses:

```bash
python3 scripts/plugin_check.py path/to/plugin-dir
python3 scripts/plugin_check.py path/to/plugin-dir --strict-inference
python3 scripts/plugin_check.py path/to/plugin-dir --manifest-key manifest-signing.pub.pem --verify
python3 scripts/plugin_check.py path/to/plugin-dir --json
```

The checker requires `plugin.py` and `bywaf.plugin.toml`, parses strict manifest
metadata, imports the plugin factory, and verifies that declared commandlets,
capabilities, secret options, and trigger specs match the code. It also runs a
lightweight AST pass over plugin source and reports inferred capabilities,
missing inferred declarations, unused declarations, and warnings for direct
network, process, and filesystem APIs that bypass framework mediation.
Inference is advisory by default; `--strict-inference` turns missing inferred
capabilities into a failed check. When `--manifest-key` is supplied, it also
verifies the manifest signature.

Generate a starter manifest from Python metadata:

```bash
python3 -m bywaf.tools.plugin_manifest path/to/plugin-dir/plugin.py
python3 -m bywaf.tools.plugin_manifest path/to/plugin-dir/plugin.py --infer-capabilities
```

The generator emits commandlet rows, declared capabilities, secret options, and
provider-owned trigger specs. With `--infer-capabilities`, AST-inferred
capabilities are merged into the manifest only when the plugin exposes exactly
one commandlet; multi-commandlet plugins still need the author to assign
inferred capabilities to the right commandlet manually.

Sign a plugin manifest outside the Bywaf interpreter:

```bash
python3 scripts/plugin_manifest_sign.py \
  --manifest path/to/plugin-dir/bywaf.plugin.toml \
  --private manifest-signing.pem \
  --in-place
```

# Plugin Catalog Signing

Bywaf keeps runtime plugin loading separate from maintainer release tooling. The
maintainer-side catalog helper builds a reviewed catalog from bundled plugin
source files and sidecar manifests, records SHA-256 hashes, and can sign that
catalog with an encrypted Ed25519 key:

```bash
python3 scripts/plugin_catalog.py build --output dist/plugin-catalog.json
python3 scripts/plugin_catalog.py generate-key \
  --private maintainer-plugin-signing.pem \
  --public maintainer-plugin-signing.pub.pem
python3 scripts/plugin_catalog.py sign \
  --catalog dist/plugin-catalog.json \
  --private maintainer-plugin-signing.pem \
  --signer "Bywaf maintainer" \
  --output dist/plugin-catalog.signed.json
python3 scripts/plugin_catalog.py verify \
  --catalog dist/plugin-catalog.signed.json \
  --public maintainer-plugin-signing.pub.pem \
  --check-tree
```

`verify` checks the catalog signature. `--check-tree` additionally checks that
the current plugin modules and sidecar manifests still match the hashes and
metadata in the signed catalog. This is the beginning of plugin chain-of-custody
support; runtime trust prompts, revocation policy, and external plugin package
distribution are still design items.

# Testing a Plugin

Unit test the commandlet directly:

```python
from pathlib import Path
import tempfile
import unittest

from bywaf.db import EventStore
from bywaf.plugin import CommandContext
from plugin import FileInfo


class FileInfoTests(unittest.TestCase):
    def test_file_info_emits_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "sample.txt")
            path.write_text("hello")
            db = EventStore(Path(tmp, "db.sqlite3"))
            context = CommandContext(db, source="file_info")

            events = list(FileInfo().run(context, [str(path)], []))

            self.assertEqual(events[0]["size"], 5)
```

For framework-level tests, load the plugin through `PluginRegistry` and execute
it with `Runner`.

# Practical Guidelines

Keep commandlets small. A commandlet should usually do one thing and publish a
clear event topic.

Use structured events. Prefer:

```python
{"host": "127.0.0.1", "port": 80, "protocol": "tcp"}
```

over unstructured strings.

Declare `consumes` and `emits`. Those fields make `cmds`, help text, completion,
and pipeline behavior easier to understand.

Put expensive or long-running work behind clear options. Add `--timeout`,
`--limit`, or similar controls where appropriate.

Use `-s` or `--silent` for commandlets that print discovery alerts. The bundled
scanner commandlets use that convention. Plugins should emit console alerts
through the context instead of calling `print()` directly:

```python
context.alert("discovered host 127.0.0.1", silent=parsed.silent)
```

This writes a structured `console.alert` event for GUI/audit consumers and
mirrors the alert to stdout unless `silent` is true. Internally,
`context.alert()` first records `framework.console.alert.requested`; the
interpreter then validates that request, writes `console.alert`, and owns the
actual terminal output. This keeps multiprocessing output ordered and gives GUI
or web frontends a clean event stream to render.

Use `context.output()` for normal command output, such as listing rows or
printing a status message:

```python
context.output("scan complete")
context.table(
    [{"host": "127.0.0.1", "ports": 3}],
    ("host", "ports"),
)
```

`context.output()` records `framework.console.output.requested`; the interpreter
then writes a `console.output` event and owns the actual print. Advanced plugins
can call `context.request(topic, payload)` directly when Bywaf grows new
framework request types.

Prefer completion specs for common cases and custom completion only when the
generic specs are not expressive enough.
