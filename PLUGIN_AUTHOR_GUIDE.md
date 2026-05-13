# Writing Bywaf Plugins

This guide shows how to write a small Bywaf plugin and how to make it pleasant
to use from the interactive shell.

Bywaf plugins provide commandlets. A commandlet is a small class with:

- a `CommandSpec`, which describes the commandlet
- a `run()` method, which performs the work
- a `plugin()` factory function, which returns the commandlet instance

Commandlets can publish events by yielding dictionaries. The runner inserts
those dictionaries into SQLite under the first topic listed in `spec.emits`.

# A Minimal Commandlet

Create a plugin directory:

```text
.bywaf/plugins/hello/
  plugin.py
```

Put this in `.bywaf/plugins/hello/plugin.py`:

```python
from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, CommandSpec, Commandlet


class Hello:
    spec = CommandSpec(
        name="hello",
        description="Say hello and emit a greeting event.",
        usage="hello [name]",
        examples=("hello", "hello world"),
        emits=("hello.greeting",),
    )

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        name = args[0] if args else "world"
        context.output(f"hello, {name}")
        yield {"name": name, "message": f"hello, {name}"}


def plugin() -> Commandlet:
    return Hello()
```

If your commandlet uses `argparse`, inherit from `CommandletBase` and call
`self.parser()` so the parser name stays consistent with the commandlet spec:

```python
from bywaf.plugin import CommandletBase


class Hello(CommandletBase):
    spec = CommandSpec(...)

    def run(self, context, args, input_events):
        parser = self.parser()
        parser.add_argument("name", nargs="?", default="world")
        parsed = parser.parse_args(args)
        context.output(f"hello, {parsed.name}")
        yield {"name": parsed.name}
```

Load and run it:

```text
bywaf> load plugin=hello
loaded hello
bywaf> hello world
hello, world
#1 hello.greeting {'name': 'world', 'message': 'hello, world'}
```

Show the events:

```text
bywaf> show hello.greeting
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
- `context.pipeline_id`, `context.command_run_id`, `context.job_id`: run scope
- `context.parent_command_run_id`: upstream pipeline stage, if any
- `context.background`: whether the commandlet is running in the background
- `context.input_high_watermark`: highest upstream event ID already consumed
- `context.require_db()`: return the active DB or raise a clear error
- `context.require_foreground()`: reject background execution for unsafe actions
- `context.output(text)`: request normal console output from the framework
- `context.alert(message)`: request an operator alert from the framework
- `context.table(rows, columns)`: print small tabular command output
- `context.page_file(path)`: request frontend-owned paging for a local file
- `context.request(topic, payload)`: advanced escape hatch for framework requests
- `context.cancelled()`: whether a soft-cancellation request is pending
- `context.raise_if_cancelled()`: raise if cancellation is pending

For beginner plugins, the core loop is usually:

```python
context.output("starting scan")
context.alert("discovered host 127.0.0.1")
context.page_file("report.txt")
yield {"host": "127.0.0.1", "status": "up"}
```

Those helpers keep plugin code simple while still routing display and audit
state through the framework-owned event bus.

Use `context.events` instead of raw `context.db` for event-bus work:

```python
for event in context.events.fetch(("host.found",), after_id=context.input_high_watermark):
    context.events.publish("example.seen_host", {"host": event.payload["host"]})
```

`context.events` records `db.read:<topic>` and `db.write:<topic>` capability
usage. Raw `context.db` remains available for privileged/internal framework
commandlets during the transition; accessing it records `db.raw`, and
third-party plugins should avoid it.

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

At launch time, Bywaf captures the effective commandlet and global variables
for each `command_run_id` and stores that snapshot in SQLite. During execution,
`context.vars.get()` checks the run snapshot first, then falls back to the
session variable store. This lets two background runs of the same commandlet
keep different values even if the operator changes session variables after the
first job starts. It also means `show run=<id>` can report the variables that
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
bywaf> load plugin=file_info
loaded file_info
bywaf> file_info READ<TAB>
bywaf> file_info README.md
#1 file.info {'path': 'README.md', 'size': 12345, 'is_dir': False}
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
bywaf> vars file_info.timeout=10
```

# Loading and Packaging Plugins

During development, plain plugin names resolve under:

```text
.bywaf/plugins
```

So:

```text
bywaf> load plugin=file_info
```

loads:

```text
.bywaf/plugins/file_info/plugin.py
```

Explicit paths also work:

```text
bywaf> load plugin=./scratch/file_info
bywaf> load plugin=~/bywaf-plugins/file_info
```

Bundled plugins live under `bywaf/plugins/` and are loaded from
`bywaf/plugins/plugins.json`. To make a bundled commandlet load automatically,
add its dotted module path to `default_plugins`.

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
