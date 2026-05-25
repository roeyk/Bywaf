# Bywaf Capability Model

Bywaf capabilities describe sensitive behaviors that commandlets intend to use
and that the framework can audit.

Capabilities are not currently a hard Python sandbox. Local Python plugins are
trusted code. The near-term goal is to make intended behavior explicit, make
actual behavior visible, and route sensitive actions through APIs that can be
enforced later.

## Document Index

- [Why Capabilities Exist](#why-capabilities-exist)
- [Declaring Capabilities](#declaring-capabilities)
- [Common Capability Names](#common-capability-names)
- [Capability Codes](#capability-codes)
- [Plugin Integration Types](#plugin-integration-types)
- [Audited Use](#audited-use)
- [Preferred APIs](#preferred-apis)
- [Policy and Test Mode](#policy-and-test-mode)
- [Enforcement Modes](#enforcement-modes)
- [Limits](#limits)
- [Plugin Author Implications](#plugin-author-implications)

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

Plugin manifests also declare capabilities before Python import:

```toml
[[commandlets]]
name = "http_probe"
capabilities = [
  "filesystem.read",
  "framework.console.alert",
  "network.connect",
]
```

Bywaf currently requires manifest capabilities to match
`CommandSpec.capabilities` exactly when a manifest is present. This catches
stale metadata early. Runtime policy enforcement remains the real behavior
boundary: privileged framework APIs can still audit or deny use even if a
plugin's metadata is absent, incomplete, or stale.

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

## Capability Codes

Each framework capability should also have a stable human-facing code in
`C###` format. The dotted capability name remains the semantic identifier used
in plugin metadata, documentation, and audit payloads; the `C###` code is a
compact stable shorthand for tables, prompts, reports, and operator selection.

Example:

```text
C302  framework.process.stream
```

Codes are not transient row numbers. Once assigned, a code should not be
reused for a different capability.

Accepted code ranges:

```text
C001-C099   framework core/session/completion/help
C100-C199   events and audit
C200-C299   database and artifact storage
C300-C399   process execution and OS access
C400-C499   network access
C500-C599   credential/secret/cookie access
C600-C699   policy/scope/control-plane actions
C700-C799   rendering/export/report generation
C800-C899   plugin/package management
C900-C999   reserved/experimental/local
```

`audit list capabilities` inventories declared capability names against runtime
`plugin.capability.used` and `plugin.capability.missing` evidence. Until exact
per-capability `C###` codes are assigned, the command displays the accepted
family range, the dotted name, declaring commandlets, last observed use, and all
timestamps with timezone.

## Plugin Integration Types

Capability requirements depend heavily on how a plugin integrates with other
code. Integration type is separate from workflow role: a scanner can be
native, library-backed, process-wrapped, or native-code backed.

Native plugins use Bywaf APIs and Python standard-library code. Native is the
default implementation trait when a plugin is neither library-backed nor
process-wrapped. Native plugins are the easiest to package and audit. Typical
examples are filters, correlators, renderers, exporters, and workflow helpers.
Their capabilities are usually event, artifact, filesystem, and
framework-output capabilities.

Library-backed plugins use a third-party Python package or non-Bywaf Python
library in-process, such as an HTTP client, Scapy, dnspython, or an nmap
binding. Imports from Bywaf itself or sibling bundled plugins do not make a
plugin library-backed. Library-backed plugins have lower overhead and richer
object access than parsing command output, but they share the Bywaf process.
Failures are Python exceptions or in-process crashes, so these plugins should
declare capabilities such as `network.connect`, `network.listen`,
`filesystem.read`, or `db.write:<topic>` precisely.

Process-wrapped plugins run mature external tools through framework-mediated
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

These are traits, not necessarily mutually exclusive types. A plugin can be
both library-backed and process-wrapped if it uses a third-party Python package
and also invokes a binary. A long-running service plugin is a
separate lifecycle trait. This taxonomy matters because each trait implies
different trust boundaries, deployment requirements, portability,
observability, reproducibility, and failure handling.

| Implementation trait | Typical role examples | Main risk boundary | Common capabilities |
| --- | --- | --- | --- |
| Native | filter, renderer, correlator | Bywaf API misuse | `db.read:*`, `db.write:*`, `artifact.write` |
| Library-backed | scanner, analyzer | in-process library behavior | `network.connect`, `filesystem.read`, `db.write:*` |
| Process-wrapped | scanner, fuzzer, importer | child process and tool output | `framework.process.run`, `filesystem.read` |
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

The test path should show policy conflicts and repairs just like real execution
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
