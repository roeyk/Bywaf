# Plugin Manifest Specification

This document defines the sidecar TOML manifest format used by Bywaf plugin
packages.

The manifest is not a sandbox or a replacement for plugin code. Plugin authors
still write commandlets in Python. For ordinary command-line shapes, new
plugins should prefer a bare `@commandlet` function: declare the public
arguments and options in TOML, then implement
`my_commandlet(context, cfg, input_events)` in Python.
The manifest records the plugin traits, commandlets, capabilities, options,
arguments, provider variables, event schemas, and trigger rules that Bywaf
should trust before or while loading plugin code.

The manifest exists so plugin contracts can be enforced and inspected before
arbitrary Python code is imported. It lets Bywaf reject undeclared capabilities,
build static catalog views, accept pre-load catalog variables, and give
`plugin_check` a second source of truth for human and LLM-authored plugins.

## Guide Index

- [File Names](#file-names)
- [Why Manifests Matter](#why-manifests-matter)
- [Schema](#schema)
- [Plugin Table](#plugin-table)
- [Commandlet Entries](#commandlet-entries)
- [Commandlet Options](#commandlet-options)
- [Commandlet Arguments](#commandlet-arguments)
- [Event Schema Entries](#event-schema-entries)
- [Trigger Entries](#trigger-entries)
- [Generation](#generation)
- [Validation](#validation)
- [What The Manifest Is Not](#what-the-manifest-is-not)

# File Names

Filesystem plugins use `bywaf.plugin.toml` next to `plugin.py`.

Bundled plugins use sidecar manifests named after the Python module, such as
`nikto.plugin.toml` next to `nikto.py`.

# Why Manifests Matter

A manifest has four practical jobs:

- **Enforceable contract:** capabilities, secret options, provider variables,
  and triggers must be declared before the framework trusts them.
- **Static catalog metadata:** Bywaf can list and reason about plugin providers
  without importing plugin code.
- **Pre-load configuration surface:** users can set declared catalog variables
  before the plugin is loaded.
- **Checker guardrail:** `plugin_check` can compare code and TOML so mistakes
  from humans or LLMs fail before loading.

# Schema

A manifest contains one optional `[plugin]` table, one or more
`[[commandlets]]` entries, optional `[[event_schemas]]` entries, and optional
`[[triggers]]` entries.

```toml
[plugin]
native = true
library_backed = false
process_wrapped = false
service = false
roles = ["command-provider"]
default_commandlet = "example"

[[commandlets]]
name = "example"
description = "Probe an example service."
usage = "example [options] <target>"
examples = [
  "example target=192.0.2.10 timeout=2",
]
capabilities = [
  "network.connect",
  "framework.console.alert",
]
consumes = ["host.found"]
emits = ["example.found"]
secret_options = ["password"]
provider_variables = ["proxy"]
secret_provider_variables = []
database.actions.view = true
database.actions.write = true
database.actions.manage = false

[[commandlets.arguments]]
name = "targets"
description = "explicit hosts or URLs"
nargs = "*"

[[commandlets.options]]
name = "timeout"
description = "connection timeout seconds"
default = "5"
type = "float"

[[commandlets.options]]
name = "password"
description = "password reference"
secret = true
type = "str"

[[event_schemas]]
topic = "example.found"
version = "1"
summary = "Example plugin-owned normalized result."

[[event_schemas.fields]]
name = "host"
type = "str"
required = true
description = "Affected host."

[[event_schemas.fields]]
name = "state"
type = "str"
allowed = ["open", "closed"]

[[triggers]]
name = "example-trigger"
topic = "example.event"
action_command = "example"
description = "ON example.event DO example"
action_mode = "background"
capability = "db.read:example.event"
payload_equals = { kind = "demo" }
active_job = false
exclude_commandlets = ["example"]
suppress_self_trigger = true
```

# Plugin Table

The `[plugin]` table describes plugin-level traits.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `native` | boolean | `true` when neither `library_backed` nor `process_wrapped` is true | In-process Python plugin written against the Bywaf framework API. |
| `library_backed` | boolean | `false` | Uses third-party Python libraries or non-Bywaf Python packages. |
| `process_wrapped` | boolean | `false` | Runs an external executable through the framework process API. |
| `service` | boolean | `false` | Provides a long-running or continuously available service. |
| `roles` | list of strings | `[]` | Plugin role metadata for tooling and cataloging. |
| `default_commandlet` | string | none | Optional commandlet selected when `use <provider-path>` targets a provider instead of a specific commandlet. Must name a declared commandlet. |

`native = true` conflicts with `library_backed = true` or
`process_wrapped = true`.

# Commandlet Entries

Each `[[commandlets]]` entry declares one commandlet exposed by the plugin.
Bywaf uses these fields for commandlet manifest validation, static catalog
views, pre-load variable completion, and manifest-backed commandlet config.

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `name` | string | yes | Must match the Python `CommandSpec.name` exactly. |
| `description` | string | no | Operator-facing commandlet summary. `ManifestCommandlet` uses this to build `CommandSpec`. |
| `usage` | string | no | Usage string for help/catalog output. |
| `examples` | list of strings | no | Example invocations for help/catalog output. |
| `consumes` | list of strings | no | Event topics this commandlet may consume. |
| `emits` | list of strings | no | Event topics this commandlet may emit. |
| `capabilities` | list of strings | no | Must match `CommandSpec.capabilities` exactly. |
| `database.actions.view` | boolean | no | Whether the commandlet may use audited database read capabilities such as `db.read:*`. Must match `CommandSpec.database_actions`. |
| `database.actions.write` | boolean | no | Whether the commandlet may use audited database write capabilities such as `db.write:*`. Must match `CommandSpec.database_actions`. |
| `database.actions.manage` | boolean | no | Whether the commandlet may use high-risk database management capabilities such as `db.raw` or `db.manage:*`. Must match `CommandSpec.database_actions`. |
| `secret_options` | list of strings | no | Must match Python options declared with `secret=True` exactly. For manifest-backed commandlets, this is normally inferred from `[[commandlets.options]] secret = true`, but the field remains accepted for explicit manifests and older commandlets. |
| `provider_variables` | list of strings | no | Immediate-provider variable names this commandlet may read with `context.vars.get_provider(...)`. Must match `CommandSpec.provider_variables` exactly. |
| `secret_provider_variables` | list of strings | no | Immediate-provider variable names that are secret references. Must match `CommandSpec.secret_provider_variables` exactly. |

Database action flags are coarse guardrails around audited DB capability use.
For example, a read-only view commandlet can declare:

```toml
[[commandlets]]
name = "ports"
capabilities = ["framework.console.output"]
database.actions.view = true
database.actions.write = false
database.actions.manage = false
```

Filesystem plugins default to runtime capability enforcement. A filesystem
plugin that calls `context.output(...)`, runs a process, writes an artifact, or
publishes an event must declare the matching capability or implied event
schema. Bundled commandlets default to audit mode, but use the same validation
machinery.

`view` permits `db.read:*`; `write` permits `db.read:*` and `db.write:*`;
`manage` permits all database actions, including raw or management access.
Lifecycle/audit events emitted by the framework itself are separate from these
plugin action flags.

Commandlets that mix read-only and mutating actions may declare the broad
allowed set here and narrow the effective action in Python for a specific argv.
Bywaf records that effective action in `command.run.arguments`, so runtime
listings and audit review can distinguish `report status=all` from
`report accept all` without relying on command-name heuristics.

When a manifest is present, Bywaf registers only commandlets listed in
`[[commandlets]]`. Extra commandlets returned by `plugin()` or `plugins()` are
ignored. Commandlets declared in the manifest but missing from Python code cause
plugin loading to fail.

# Commandlet Options

`[[commandlets.options]]` entries belong to the nearest preceding
`[[commandlets]]` entry. They describe public named options such as
`timeout=5` or `binary=traceroute`. Boolean options may be written as
`silent=true` or as binary flags such as `--silent`.

For manifest-backed functions and `ManifestCommandlet`, options are also the
source of the per-run immutable `cfg` object passed to plugin behavior. Values
resolve in this order:

```text
command-line option > stored plugin variable > manifest default
```

The `cfg` object is a snapshot for one invocation. If the operator changes a
plugin variable while a commandlet is running, the running invocation keeps its
existing `cfg`; ordinary plugin variables configure future invocations, not live
control state.

By convention, bare `@commandlet` reads the sidecar manifest next to its module,
such as `dns_lookup.plugin.toml`, and uses the module stem as the commandlet
name. Package-style plugins with `bywaf.plugin.toml` use the function name as
the commandlet name. Class-based `ManifestCommandlet` remains available for
advanced commandlets that need override hooks.

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `name` | string | yes | Public option name. Hyphens are converted to underscores on `cfg`, so `record-type` becomes `cfg.record_type`. |
| `description` | string | no | Help text for completion and docs. |
| `default` | string, integer, float, boolean, or null | no | Default value. Values are normalized to strings in `CommandSpec`; the manifest-backed adapter casts them back using `type`. |
| `choices` | list of strings | no | Allowed values. |
| `completion` | string | no | Completion kind such as `path`, `file`, `dir`, `event-topic`, or `none`. |
| `secret` | boolean | no | Marks the option as secret metadata and adds it to the effective secret option list. |
| `type` | string | no | One of `str`, `int`, `optional-int`, `float`, or `bool`. Defaults to `str`. |

Example:

```toml
[[commandlets.options]]
name = "record-type"
description = "DNS record type"
default = "A"
choices = ["A", "AAAA", "CNAME", "MX", "TXT"]
type = "str"

[[commandlets.options]]
name = "timeout"
description = "resolver timeout seconds"
default = "5"
type = "float"

[[commandlets.options]]
name = "silent"
description = "suppress console alerts"
default = false
type = "bool"
```

Boolean options accept explicit values (`silent=true`, `--silent=false`) and
also behave as flags when written as `--silent`.

# Commandlet Arguments

`[[commandlets.arguments]]` entries belong to the nearest preceding
`[[commandlets]]` entry. They describe positional arguments. The
manifest-backed adapter parses them into `cfg` with the same naming rule as
options: hyphens become underscores.

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `name` | string | yes | Argument name. |
| `description` | string | no | Help text for completion and docs. |
| `nargs` | string or integer | no | Standard argparse-style arity, such as `?`, `*`, `+`, or an integer count. |
| `completion` | string | no | Completion kind such as `path`, `file`, `dir`, `host`, or `none`. |

Example:

```toml
[[commandlets.arguments]]
name = "targets"
description = "explicit host, host:port, or URL targets"
nargs = "*"
completion = "host"
```

Use positional arguments for natural command syntax, and use options for values
that the operator may want to persist with `set` or override by name.

# Event Schema Entries

`[[event_schemas]]` entries declare plugin-owned normalized event topics. They
are for topics that are stable enough for other plugins and inventory/report
views to consume, but not yet framework-known. Scanner-private raw topics can
remain undeclared and free-form.

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `topic` | string | yes | Event topic owned by this plugin. It must not override a framework-owned schema such as `host.found` or `port.open`. |
| `version` | string | no | Schema version understood by producers and consumers. Defaults to `"1"`. |
| `summary` | string | no | Human-readable description of the fact represented by this topic. |
| `notes` | list of strings | no | Additional guidance for plugin authors or views. |

`[[event_schemas.fields]]` entries belong to the nearest preceding
`[[event_schemas]]` entry.

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `name` | string | yes | Payload field name. |
| `type` | string | no | One of `any`, `bool`, `dict`, `int`, `list`, `number`, or `str`. Defaults to `any`. |
| `required` | boolean | no | Whether the field must be present. |
| `description` | string | no | Field description. |
| `allowed` | list of strings | no | Optional allowed values. Values are compared as strings. |

Bywaf registers these schemas when the plugin manifest is loaded. `plugin_check`
uses them to validate literal `context.events.publish(...)` payloads and to
require matching `emits` declarations for schema-backed topics.

# Trigger Entries

Each `[[triggers]]` entry declares one provider-owned trigger rule.

| Key | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `name` | string | yes | none | Trigger name. |
| `topic` | string | yes | none | Event topic watched by the trigger. |
| `action_command` | string | yes | none | Command invoked when the trigger fires. |
| `description` | string | no | `""` | Human-readable explanation. |
| `action_mode` | string | no | `service` | One of `foreground`, `background`, or `service`. |
| `capability` | string | no | none | Capability associated with this trigger. |
| `payload_equals` | table of string values | no | `{}` | Exact string payload predicates. |
| `active_job` | boolean | no | `false` | Whether an active job condition is required. |
| `exclude_commandlets` | list of strings | no | `[]` | Commandlets ignored for loop prevention or filtering. |
| `suppress_self_trigger` | boolean | no | `true` | Prevents the trigger from reacting to its own action output. |

Manifest trigger entries must match the trigger specs exposed by Python code.
Missing, undeclared, duplicate, or changed triggers fail validation.

# Generation

Use `bywaf-plugin-manifest` to generate a starter manifest from a plugin:

```text
bywaf-plugin-manifest path/to/plugin.py
bywaf-plugin-manifest --library-backed path/to/plugin.py -o bywaf.plugin.toml
bywaf-plugin-manifest --process-wrapped --service path/to/plugin.py
```

The generator uses runtime inspection as the source of truth. It imports the
plugin module, loads commandlets and triggers, and emits TOML from the runtime
specs that Bywaf sees.

`--infer-capabilities` adds a static AST analysis pass. That pass scans Python
source for recognizable framework calls and direct Python APIs that imply
capabilities. It is an aid for reviewers, not a complete static proof of plugin
behavior.

# Validation

Bywaf validates manifest fields using strict TOML types for the fields it
understands. Strings must be strings, booleans must be booleans, and list fields
must contain strings.

Unknown keys are not a public extension mechanism. They may be tolerated by the
current parser, but Bywaf does not use them for commandlet registration,
completion, emitted topics, argument parsing, or help output. Keep commandlet
metadata in Python unless this specification lists the field.

The loader enforces these consistency checks:

- every manifest commandlet exists in Python code;
- manifest `capabilities` match Python `CommandSpec.capabilities`;
- manifest `[[commandlets.options]]` match Python `CommandSpec.options` when
  option rows are present;
- manifest `[[commandlets.arguments]]` match Python `CommandSpec.arguments`
  when argument rows are present;
- manifest `secret_options` match Python secret option metadata;
- manifest `database.actions.*` flags match Python `CommandSpec.database_actions`;
- manifest triggers match Python trigger specs;
- trigger `action_mode` is `foreground`, `background`, or `service`;
- duplicate trigger names in one manifest are rejected.

The manifest is a consistency and trust boundary. It is not the only runtime
policy layer. Framework APIs still audit and can deny behavior according to
runtime policy.

# What The Manifest Is Not

The manifest is not a replacement for the Python plugin API. It can define the
ordinary command-line interface for manifest-backed functions and classes, but
the commandlet still owns behavior, validation beyond simple type/choice
checks, event publishing, artifacts, and follow-up logic in Python.

It does not currently define a complete pre-import execution catalog. Bywaf can
read manifest metadata before plugin import for listing, completion, declared
variables, and checks, but execution still imports trusted plugin code.

It is not a sandbox. Native and library-backed plugins are still Python code.
Signatures and manifest checks establish provenance and detect drift; they do
not make untrusted plugin code safe to execute.
