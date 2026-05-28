# Plugin Manifest Specification

This document defines the sidecar TOML manifest format used by Bywaf plugin
packages.

The manifest is not the plugin API. Plugin authors still write commandlets in
Python with `CommandletBase`, `@commandlet`, `@argument`, `@option`, and
`run(context, args, input_events)`. The manifest records the plugin traits,
commandlets, capabilities, secret options, and trigger rules that Bywaf should
trust before or while loading plugin code.

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
`[[commandlets]]` entries, and optional `[[triggers]]` entries.

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
capabilities = [
  "network.connect",
  "framework.console.alert",
]
secret_options = ["password"]
provider_variables = ["proxy"]
secret_provider_variables = []

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
Only the keys below are used by Bywaf for commandlet manifest validation.
Descriptions, examples, `emits`, `consumes`, and runtime argument metadata
belong in Python `@commandlet`, `@argument`, and `@option` declarations.

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `name` | string | yes | Must match the Python `CommandSpec.name` exactly. |
| `capabilities` | list of strings | no | Must match `CommandSpec.capabilities` exactly. |
| `database.actions.view` | boolean | no | Whether the commandlet may use audited database read capabilities such as `db.read:*`. Must match `CommandSpec.database_actions`. |
| `database.actions.write` | boolean | no | Whether the commandlet may use audited database write capabilities such as `db.write:*`. Must match `CommandSpec.database_actions`. |
| `database.actions.manage` | boolean | no | Whether the commandlet may use high-risk database management capabilities such as `db.raw` or `db.manage:*`. Must match `CommandSpec.database_actions`. |
| `secret_options` | list of strings | no | Must match Python options declared with `secret=True` exactly. |
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

`view` permits `db.read:*`; `write` permits `db.read:*` and `db.write:*`;
`manage` permits all database actions, including raw or management access.
Lifecycle/audit events emitted by the framework itself are separate from these
plugin action flags.

When a manifest is present, Bywaf registers only commandlets listed in
`[[commandlets]]`. Extra commandlets returned by `plugin()` or `plugins()` are
ignored. Commandlets declared in the manifest but missing from Python code cause
plugin loading to fail.

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
- manifest `secret_options` match Python secret option metadata;
- manifest triggers match Python trigger specs;
- trigger `action_mode` is `foreground`, `background`, or `service`;
- duplicate trigger names in one manifest are rejected.

The manifest is a consistency and trust boundary. It is not the only runtime
policy layer. Framework APIs still audit and can deny behavior according to
runtime policy.

# What The Manifest Is Not

The manifest is not a replacement for the Python plugin API.

It does not define runtime argument parsing. Plugin authors still parse
execution arguments inside `run()` with `self.parser()` and standard argparse
calls.

It does not currently define a full pre-import help/completion catalog. Bywaf
can read manifest metadata before plugin import in some trust paths, but the
manifest is primarily a sidecar trust and consistency document.

It is not a sandbox. Native and library-backed plugins are still Python code.
Signatures and manifest checks establish provenance and detect drift; they do
not make untrusted plugin code safe to execute.
