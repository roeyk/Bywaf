# Plugin Author Workflow

This is the recommended loop for creating or changing a Bywaf plugin.

## 1. Start From A Scaffold Or Skeleton

For a small one-commandlet native plugin, start with the scaffold command:

```bash
python3 scripts/plugin_new.py my_probe --output /tmp/my_probe
```

It creates `plugin.py`, `bywaf.plugin.toml`, a focused test stub, and a short
README using the current manifest-backed `@commandlet` pattern.

The scaffold is the right starting point when the plugin is native Python, has
one commandlet, and can emit one plugin-owned fact topic without a third-party
library, wrapped binary, background service, or complex finding-packaging
layout.

For a small bundled-native plugin that ships under `bywaf/plugins/...`, use:

```bash
python3 scripts/plugin_new.py my_probe --bundled http
```

After scaffolding, the plugin writer inserts code in the generated commandlet
function first:

- external plugins: edit `plugin.py`, inside `my_probe(context, cfg,
  input_events)`;
- bundled plugins: edit `__init__.py`, inside `my_probe(context, cfg,
  input_events)`;
- replace the placeholder yielded payload with the plugin-owned fact;
- keep `bywaf.plugin.toml` synchronized with the behavior: arguments, emitted
  topics, capabilities, database actions, and event schema fields;
- when the logic grows, move pure probing/parsing into helper functions or
  split files such as `detect.py`, while keeping the commandlet file as the thin
  entry point.

For more complex plugin shapes, pick the closest skeleton instead of inventing
a layout:

- `native_minimal` for a small pure-Python commandlet
- `native_vulnerability` for a detection plugin that emits findings
- `library_backed` for a Python library integration
- `process_wrapped` for an external binary wrapper
- `service_trigger_provider` for a long-running provider with triggers

Copy it into a scratch plugin directory and keep the sidecar
`bywaf.plugin.toml`.

Bundled scaffold output creates the package layout and manifest `module = ...`
entry, but it does not finish the whole bundled-plugin workflow. After using
`--bundled`, update the bundled registry, bundled manual, tests, and changelog.

## 2. Declare The Manifest First

The manifest is the pre-import trust boundary. It should say what Bywaf can know
without running plugin Python:

- commandlet names
- arguments and options
- capabilities
- database actions
- consumed and emitted topics
- secret options
- provider variables
- plugin-owned event schemas
- required Bywaf version

Do not use Python registration side effects for interoperability metadata.
Every filesystem plugin manifest must include a non-empty `[plugin].version`.
Use `requires_bywaf` when the plugin depends on a minimum Bywaf API version.

## 3. Keep Plugin Code Small

Prefer this shape:

```text
plugin.py          @commandlet function and plugin() factory
command.py         commandlet orchestration
detect.py          pure detection logic
findings.py        finding payload helpers
models.py          local domain objects
bywaf.plugin.toml  manifest contract
```

For new commandlets, prefer the bare `@commandlet` decorator and manifest-backed
`cfg` object. Use `CommandletBase` only when you need unusual parsing,
completion, or lifecycle hooks.

## 4. Run The Checker Early

Run the checker before loading the plugin:

```bash
python3 scripts/plugin_check.py path/to/plugin-dir --strict-inference
```

Fix checker output before writing more code. The checker catches drift between
Python metadata and manifest declarations, including capabilities, topics,
options, schemas, and signatures.

If you generate or update manifest metadata, review the generated TOML before
trusting it. Generated declarations should be deterministic and reviewable, not
magic.

## 5. Add Tests At The Right Layer

Test pure logic first:

- parser/detector input and output
- finding payload builders
- schema-object serialization/deserialization
- wrapper parsers against fixtures

Then test the commandlet path through `Runner` or `CommandContext`:

- variables and `cfg`
- input events
- emitted topics
- capabilities and database actions
- artifacts and raw evidence
- error and timeout behavior

Avoid live internet dependencies. Use local fixtures, fake process results, and
temporary databases.

## 6. Load Only After It Checks

For local development:

```text
bywaf> plugin load=./path/to/plugin --force
bywaf> help your_command
bywaf> your_command --help
```

`--force` is a development override. Do not treat it as a substitute for the
checker, manifest review, tests, or signing.

## 7. Sign Or Package

When the plugin is ready for distribution:

- keep version and `requires_bywaf` accurate
- sign the manifest/catalog where applicable
- include fixture tests and docs
- document external tool or library requirements
- record emitted schemas/topics and safety boundaries

## 8. Review Safe Defaults

Before merging a bundled plugin, check:

- [Safe Defaults Checklist](../SAFE_DEFAULTS_CHECKLIST.md)
- [Wrapper Robustness](wrapper-robustness.md) for external tools
- [Vulnerability Plugin Guide](vulnerability-plugins.md) for findings
- [Shared Event Schemas](event-schemas.md) for normalized facts

The secure path should be the easiest path: manifest first, checker early,
small code, fixture tests, explicit capabilities, and normalized events.
