# Plugin Fundamentals

Start here for plugin kinds, manifest basics, the current public API, and small complete examples.

## Contents

- [Plugin Types](#plugin-types)
- [Plugin Manifest](#plugin-manifest)
- [Manifest Generation And Inspection](#manifest-generation-and-inspection)
- [Current API, Not Generic Plugin Patterns](#current-api-not-generic-plugin-patterns)
- [Defining Inputs: Arguments vs Options](#defining-inputs-arguments-vs-options)
- [A Minimal Commandlet](#a-minimal-commandlet)
- [Complete External Plugin Example](#complete-external-plugin-example)

## Plugin Types

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
  `framework.process.run` or `framework.process.stream`; blocking
  `context.process.run()` wrappers should also declare `artifact.write` because
  Bywaf attaches a redacted stdout/stderr transcript artifact for each run.
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

## Plugin Manifest

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
default_commandlet = "example"

[[commandlets]]
name = "example"
capabilities = ["network.connect"]
database.actions.view = true
database.actions.write = true
database.actions.manage = false
secret_options = ["password"]
provider_variables = ["proxy"]
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

Each `[[commandlets]]` entry should also list the commandlet capabilities,
database action policy, `consumes` and `emits` topics, secret options, and any
immediate provider variables the commandlet may read. Bywaf requires manifest
`capabilities`, `database.actions.*`, `secret_options`, `provider_variables`,
and `secret_provider_variables` to match Python metadata exactly. When
`consumes` or `emits` are present in the manifest, they must match
`CommandSpec`; plugin-check also requires shared framework event topics that
the source publishes to be declared in `emits`. This is a pre-load consistency
check, not the only enforcement layer: runtime policy still audits and can deny
actual framework API use if a plugin attempts behavior outside its declared
capabilities, database action policy, or provider-variable permissions.

## Manifest Generation And Inspection

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
| What commandlets, capabilities, topic declarations, secret options, and triggers may load? | `bywaf.plugin.toml` or bundled `*.plugin.toml`. |
| How does a commandlet parse runtime args? | Python `run()` method using `self.parser()`. |
| Does the manifest sandbox plugin code? | No. It records trust metadata and consistency expectations. |

## Current API, Not Generic Plugin Patterns

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

from bywaf.event import Event
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

## Defining Inputs: Arguments vs Options

Bywaf splits command input metadata into positional arguments and named options.
The distinction follows what the operator types:

| User input shape | Decorator | Example |
| --- | --- | --- |
| Positional value | `@argument(...)` | `cat README.md` |
| Optional positional value | `@argument(..., required=False)` | `hello` or `hello world` |
| Named setting | `@option(...)` | `portscanner port=22,80,443` |
| Named flag | `@option(...)` plus `action="store_true"` in `parser.add_argument(...)` | `portscanner --listen` |
| Secret named setting | `@option(..., secret=True)` | `ssh_probe password=...` |

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

If a plugin resolves DNS names before calling a network backend, keep address
family choices consistent with the operator's arguments. Bundled plugins use
`bywaf.plugins.addressing.filter_addresses_for_ip_family(...)` to apply `-4`
or `-6` before publishing `name.resolved` provenance or invoking the backend.

For boolean-style options, keep the metadata explicit. Use string defaults and
choices so help, completion, manifests, and the plugin checker all see the
same public contract:

```python
@option("confirm", "perform active confirmation", "false", ("true", "false"))
@option("silent", "suppress alerts", "false", ("true", "false"))
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

from bywaf.event import Event
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

## A Minimal Commandlet

Create a plugin directory:

```text
.bywaf/plugins/hello/
  plugin.py
  bywaf.plugin.toml
```

Put this in `.bywaf/plugins/hello/plugin.py`:

```python
from collections.abc import Iterable

from bywaf.event import Event
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
bywaf> plugin load=hello --force
loaded hello
bywaf> hello world
hello, world
1: hello.greeting {'name': 'world', 'message': 'hello, world'}
```

Show the events:

```text
bywaf> event hello.greeting
```

## Complete External Plugin Example

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

from bywaf.event import Event
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
        "http_header_check https://app.example.test",
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
bywaf> plugin load=http_header_check --force
bywaf> http_header_check https://example.com
bywaf> event http.headers.checked
```
