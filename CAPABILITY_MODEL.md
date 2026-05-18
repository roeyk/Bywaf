# Bywaf Capability Model

Bywaf capabilities describe sensitive behaviors that commandlets intend to use
and that the framework can audit.

Capabilities are not currently a hard Python sandbox. Local Python plugins are
trusted code. The near-term goal is to make intended behavior explicit, make
actual behavior visible, and route sensitive actions through APIs that can be
enforced later.

## Why Capabilities Exist

Pentesting workflows often handle client targets, credentials, cookies,
reports, screenshots, and scan results. Operators need to know what a plugin
was expected to do and what it actually did.

Capabilities support that by answering questions such as:

- Did this plugin read or write a topic it did not declare?
- Did this plugin request filesystem access?
- Did this plugin execute an external process?
- Did this plugin ask the framework to print, page, prompt, or alert?
- Did a policy override or repair the requested behavior?

## Declaring Capabilities

Commandlets declare capabilities on `CommandSpec`:

```python
CommandSpec(
    name="http_probe",
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

`consumes` and `emits` imply the corresponding topic capabilities for normal
event-bus use. Explicit declarations are still useful documentation for humans.

## Common Capability Names

Common capability names include:

```text
db.read:<topic>
db.write:<topic>
db.raw
framework.console.output
framework.console.alert
framework.file.page
framework.prompt.change
framework.secret.prompt
framework.process.run
framework.process.stream
framework.job.control
filesystem.read
filesystem.write
network.connect
network.listen
```

Use topic suffixes where they add clarity. Use coarser names for behavior that
does not naturally map to one resource.

## Plugin Integration Types

Capability requirements depend heavily on how a plugin integrates with other
code. Integration type is separate from workflow role: a scanner can be
framework-native, library-backed, external-process backed, or native-code
backed.

Framework-native plugins use Bywaf APIs and Python standard-library code. They
are the easiest to package and audit. Typical examples are filters,
correlators, renderers, exporters, and workflow helpers. Their capabilities are
usually event, artifact, filesystem, and framework-output capabilities.

Library-backed plugins use an in-process Python library or binding such as an
HTTP client, Scapy, or an nmap binding. They have lower overhead and richer
object access than parsing command output, but they share the Bywaf process.
Failures are Python exceptions or in-process crashes, so these plugins should
declare capabilities such as `network.connect`, `network.listen`,
`filesystem.read`, or `db.write:<topic>` precisely.

External-process wrapper plugins run mature tools through framework-mediated
process execution. Examples include wrappers around tools such as nmap, ffuf,
nikto, sqlmap, or similar utilities. They should use `context.process.run()` or
`context.process.stream()` instead of direct `subprocess` calls, and they
should declare `framework.process.run` or `framework.process.stream`. Their
failure semantics are process exit codes, stdout, stderr, timeouts, and output
files.

Native or FFI plugins load or communicate with compiled code written in C, C++,
Rust, Go, Zig, or similar languages. They may use FFI, shared libraries, IPC,
gRPC, or subprocesses. Treat these as higher-risk because ABI mismatches,
memory-safety bugs, and crashes can affect Bywaf unless they are isolated.
Future capability names may need to distinguish `ffi.load`, `ipc.connect`, and
native process boundaries.

This taxonomy matters because each type implies different trust boundaries,
deployment requirements, portability, observability, reproducibility, and
failure handling.

| Integration type | Typical role examples | Main risk boundary | Common capabilities |
| --- | --- | --- | --- |
| Framework-native | filter, renderer, correlator | Bywaf API misuse | `db.read:*`, `db.write:*`, `artifact.write` |
| Library-backed | scanner, analyzer | in-process library behavior | `network.connect`, `filesystem.read`, `db.write:*` |
| External-process wrapper | scanner, fuzzer, importer | child process and tool output | `framework.process.run`, `filesystem.read` |
| Native/FFI | high-performance analyzer | ABI and memory safety | future `ffi.load`, `ipc.connect`, `process.run` |

## Audited Use

When a plugin uses a framework API, Bywaf can record:

```text
plugin.capability.used
plugin.capability.missing
```

`plugin.capability.used` means the behavior was observed. `missing` means the
behavior was observed but was not declared by the commandlet.

This is useful even before hard enforcement because it gives operators a review
trail.

## Preferred APIs

Normal plugins should use mediated APIs:

- `context.events` for publishing and reading events;
- `context.output()` for operator output;
- `context.alert()` for live alerts;
- `context.page_file()` for paging files;
- `context.process.run()` and `context.process.stream()` for external tools;
- `context.artifacts` for storing attached evidence;
- `context.signals` for soft runtime control.

Privileged framework commandlets may use `context.db` directly. Direct database
use audits `db.raw` and should be reserved for storage/runtime commandlets that
need it.

## Policy and Test Mode

Policies are framework-level decisions that can deny, warn, or repair requested
behavior. For example, a network policy can prune a target list before a scan.

`--test` asks the commandlet and policy engine to describe the intended action
without running the real work:

```text
hostscanner 192.168.1.0/24 --test
```

The test path should show policy conflicts and repairs just like the real run
would. Operator approvals are audited with fields such as `approved_by`.

## Enforcement Modes

The intended progression is:

```text
capabilities.mode=off
capabilities.mode=audit
capabilities.mode=warn
capabilities.mode=enforce
```

Current Bywaf behavior is audit-first. Future enforcement can deny undeclared
framework requests, restrict raw database access, or isolate untrusted plugins
in separate processes.

## Limits

Capabilities alone do not make arbitrary in-process Python code safe. A hostile
plugin can still try to import modules, open files, or use sockets directly
unless stronger isolation is added.

The practical security direction is:

- make normal plugin APIs easy enough that plugin authors do not need raw
  access;
- audit sensitive operations through framework helpers;
- reserve `db.raw` and direct process access for privileged commandlets;
- add policy enforcement where the framework can reliably mediate behavior;
- use process isolation for stronger third-party plugin boundaries later.

## Plugin Author Implications

Declare what your commandlet expects to do. Use framework helpers instead of
direct filesystem, process, console, or database calls. If a plugin needs a
higher-risk capability, make that explicit in `CommandSpec` and document why.
