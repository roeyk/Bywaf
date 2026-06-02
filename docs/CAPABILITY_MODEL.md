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

Commandlets also declare coarse database action policy in both Python metadata
and the manifest:

```toml
[[commandlets]]
name = "ports"
database.actions.view = true
database.actions.write = false
database.actions.manage = false
```

`view` covers audited database reads, `write` covers reads and writes, and
`manage` covers raw or management-level database access. These flags keep
read-only view commands from silently growing write access while still allowing
the framework to record lifecycle and audit events around command execution.
Mixed commandlets can also classify the effective database action for each
invocation. For example, `report status=all` records a view action, while
`report accept all` records a write action.

## Common Capability Names

Common capability names include:

```text
db.read:<topic>
db.write:<topic>
db.raw
finding.review
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

Initial assigned codes:

| Code | Capability | Notes |
| --- | --- | --- |
| C101 | `db.read:<topic>` | Read normalized event/store topics. Topic-specific suffixes remain part of the semantic capability. |
| C102 | `db.write:<topic>` | Write normalized event/store topics. Topic-specific suffixes remain part of the semantic capability. |
| C201 | `db.raw` | Privileged direct or management database access. |
| C202 | `artifact.read` | Read artifact bodies or metadata through framework services. |
| C203 | `artifact.write` | Attach or write artifact evidence through framework services. |
| C301 | `framework.process.run` | Blocking framework-mediated process execution. |
| C302 | `framework.process.stream` | Streaming framework-mediated process execution. |
| C311 | `filesystem.read` | Direct filesystem reads or framework-mediated file attachment reads. |
| C312 | `filesystem.write` | Direct filesystem writes. |
| C401 | `network.connect` | Outbound network connections or active probes. |
| C402 | `network.listen` | Passive capture, listeners, or local network receive modes. |
| C501 | `framework.secret.prompt` | Prompting for secret input. |
| C502 | `framework.secret.resolve` | Resolving stored secret references. |
| C601 | `framework.job.control` | Job, pipeline, step, or live-control operations. |
| C602 | `finding.review` | Review-state changes such as accept, reject, or candidate ordering. |
| C701 | `framework.console.output` | Normal console output. |
| C702 | `framework.console.alert` | Operator-visible alerts. |
| C703 | `framework.file.page` | Pager/file display output. |
| C704 | `framework.render.table` | Framework table/render provider output. |
| C801 | `plugin.progress` | Plugin progress events. |

Do not assign a new top-level code in this table only because a topic-specific
capability exists. For example, `db.write:host.found` uses the semantic name
`db.write:host.found` and belongs under the C102 family.

For checker and audit display, topic-specific `db.read:<topic>` and
`db.write:<topic>` capabilities use stable dotted subcodes under their assigned
families. The subcode is derived deterministically from the exact topic string,
so the displayed code remains stable without maintaining a registry entry for
every topic. This keeps semantic capability names exact while making review
output more explicit than a broad family label.

`audit list capabilities` inventories declared capability names against runtime
`plugin.capability.used` and `plugin.capability.missing` evidence. Runtime
audit and checker output display exact assigned codes for known capabilities,
stable dotted subcodes such as `C102.224929` for topic-specific capabilities,
and accepted family ranges for future or unassigned capabilities.

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
- `context.pipeline.stop()` for deliberate downstream pipeline stops;
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

Current Bywaf behavior is audit-first for bundled commandlets and
secure-by-default for filesystem plugins: external filesystem plugins run with
capability enforcement unless the operator explicitly sets
`global.capabilities.mode`.

Set `global.capabilities.mode` to choose behavior:

- `off`: suppress capability audit events. Use only for narrow debugging.
- `audit`: record `plugin.capability.used` and `plugin.capability.missing`
  without blocking execution. This is the bundled-plugin default.
- `warn`: currently equivalent to `audit`; reserved for a later
  operator-visible warning mode.
- `enforce`: deny undeclared mediated framework capabilities after recording
  the missing-capability evidence.

Enforcement applies where Bywaf mediates behavior: `context.events`,
`context.process`, `context.output`, `context.artifacts`, `context.signals`,
framework render/page requests, and other context APIs. Database action flags
are enforced separately for mediated DB capabilities: an invocation whose
effective `database.actions.*` permits only `view` cannot use
`db.write:<topic>` through the normal context APIs.

Bundled and third-party plugins use the same mediated enforcement logic, but
they do not use the same default. Bundled plugins are reviewed with the
framework and default to audit mode. Filesystem plugins are external code and
default to enforcement so missing declarations fail closed during normal
operator use. Set `global.capabilities.mode=audit` only when deliberately
developing or debugging a plugin manifest.

## Limits

Capabilities alone do not make arbitrary in-process Python code safe. A hostile
plugin can still try to import modules, open files, or use sockets directly
unless stronger isolation is added.

Plugins are intentionally data-aware, not topology-aware. A commandlet can read
its own execution IDs, consume upstream events, publish normalized results, and
request `context.pipeline.stop()` when continuing would be wrong. It should not
receive the full parsed pipeline, downstream commandlet list, or its ordinal
position in the operator's expression. That boundary limits how much strategic
information a plugin gets about the broader workflow and keeps cross-stage
coordination mediated through events and framework requests.

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
