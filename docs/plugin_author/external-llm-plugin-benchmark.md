# External LLM Plugin Benchmark

This page defines a small conformance exercise for evaluating whether an
outside AI assistant can follow Bywaf's plugin author documentation without
inventing framework APIs.

**Audience**

This document is for maintainers evaluating AI-generated plugin drafts and for
plugin authors who want a compact self-test of the documented plugin workflow.

**Related Documents**

- [Documentation Paths](../DOCUMENTATION_PATHS.md): role-based reading
  sequences; use the Plugin Developer path before attempting this benchmark.
- [Plugin Author Guide](README.md): plugin author entry point.
- [Plugin Fundamentals](fundamentals.md): current API, manifest basics, and a
  complete plugin example.
- [Commandlet API Reference](commandlet-api.md): commandlet specs, context
  APIs, parsing, and event flow.
- [Plugin Packaging And Checking](packaging-and-checking.md): checker and
  manifest validation.
- [Plugin Testing And Guidelines](testing-and-guidelines.md): focused plugin
  test expectations.
- [LLM-Assisted Plugin Authoring](llm-assisted-authoring.md): checker loop and
  prompt guidance for AI-generated plugins.

## Benchmark Goal

Ask an outside assistant to create a small `http_title` filesystem plugin. The
plugin should fetch a single HTTP or HTTPS URL, extract the page title, and
emit one structured event.

This benchmark fits the current scaffold scope: small external native plugin,
one commandlet, one input, and one plugin-owned topic. The assistant should use
`scripts/plugin_new.py` to create the initial directory, then edit the generated
files rather than inventing the layout from scratch.

Treat `http.title` as a plugin-owned event topic for this benchmark unless the
current documentation defines a shared framework topic for HTTP titles.

The point is not title extraction sophistication. The point is whether the
assistant can follow the documented Bywaf plugin contract:

- correct filesystem plugin layout;
- current commandlet API, not a generic plugin framework;
- sidecar manifest with synchronized commandlet metadata;
- explicit capabilities, emitted topic, and plugin-owned event schema;
- bounded network behavior with a timeout;
- JSON-serializable event payloads;
- focused tests that avoid live network dependency;
- passing `plugin_check --strict-inference --llm-feedback`.

## Suggested Prompt

```text
Read the Bywaf Plugin Developer path in docs/DOCUMENTATION_PATHS.md, then read
the referenced plugin author docs needed for this task. Create a complete
filesystem plugin directory named http_title.

Start by using scripts/plugin_new.py to generate the initial http_title
scaffold in a scratch directory. Then modify only what is necessary to implement
the behavior below. Do not write the plugin layout from scratch.

The plugin must:
- provide one commandlet named http_title;
- accept one required positional URL argument;
- use the current Bywaf commandlet API only;
- fetch http:// or https:// URLs using the Python standard library;
- use a bounded timeout;
- extract the HTML <title> text when present;
- emit one JSON-serializable event on topic http.title;
- treat http.title as a plugin-owned event topic for this benchmark unless the
  documentation defines a shared framework topic for HTTP titles;
- declare the matching capabilities, emitted topic, argument, plugin-owned
  event schema, and database action policy in bywaf.plugin.toml;
- include focused tests that do not require external network access;
- include the exact plugin_check command that should pass.
- do not use console output as the primary result channel; the structured event
  is the result.

Do not use BaseCommandlet, info dictionaries, modules/ layouts, Metasploit
module patterns, exploit/run entrypoints, or undeclared framework APIs.
Output the full directory tree and complete file contents.
```

## Expected Shape

The generated package should look like:

```text
http_title/
  plugin.py
  bywaf.plugin.toml
  tests/
    test_http_title.py
```

The exact implementation may vary, but the reviewer should see:

- `plugin.py` exporting `def plugin() -> Commandlet`;
- a commandlet whose Python metadata matches the TOML manifest;
- `network.connect` for the outbound HTTP request;
- `framework.console.output` or `framework.console.alert` only if the code uses
  the matching context method;
- `emits = ["http.title"]` in TOML and `emits=("http.title",)` in Python;
- a `[[event_schemas]]` entry for `http.title` with stable field metadata;
- `database.actions.write = true` in TOML and `database_actions=("write",)` in
  Python if the class-based decorator form is used;
- a payload with stable fields such as `url`, `title`, `status_code`, and
  `error`;
- tests that patch the HTTP connection or local fetch helper instead of calling
  the public internet.

## Single-Shot Checklist

Before submitting the plugin, check these common failure points:

- Use current imports from `bywaf.plugin`, such as `CommandContext`,
  `Commandlet`, `CommandletBase`, `@commandlet`, and `@argument`; do not import
  from `bywaf.framework`.
- Return `def plugin() -> Commandlet`, not `Commandlet(name=..., handler=...)`.
- In `bywaf.plugin.toml`, use `capabilities = [...]` inside the matching
  `[[commandlets]]` row; do not create a separate `[capabilities]` table.
- Use manifest event-schema field types exactly as documented: `str`, `int`,
  `bool`, `dict`, `list`, `number`, or `any`; do not use `string` or
  `integer`.
- Do not put `required = true`, `positional = true`, or `type = "string"`
  under `[[commandlets.arguments]]`. Requiredness is inferred from `nargs`;
  with no `nargs`, the positional argument is required.
- Keep manifest commandlet metadata aligned with Python metadata. For
  class-based commandlets, the `[[commandlets.arguments]] description` should
  match the `@argument(...)` description.
- Declare `framework.console.output` or `framework.console.alert` only if the
  plugin actually calls `context.output()` or `context.alert()`.
- If tests use fake connection classes, make the fake response configurable or
  use a `Mock` connection object. Do not set `.return_value` on a normal fake
  method.
- Tests should import from the scratch plugin layout the same way the checker
  sees it, for example `from plugin import HttpTitle` when `plugin.py` is at
  the package root used in `PYTHONPATH`.

## Pass Criteria

The draft passes the benchmark only when all of these are true:

1. `python3 scripts/plugin_check.py path/to/http_title --strict-inference --llm-feedback`
   exits successfully.
2. Focused tests pass locally.
3. Manual review finds no invented Bywaf API names or legacy plugin patterns.
4. The plugin emits structured facts rather than using console output as the
   primary interface.
5. Error paths emit bounded, JSON-serializable payloads and do not hide
   unexpected network failures behind vague success messages.

Expected checker notes:

- Direct standard-library network use, such as `http.client.HTTPConnection`,
  may be reported as a review note when `network.connect` is declared. That is
  acceptable for this benchmark.
- Unused capability notes are not acceptable in the final draft. Remove unused
  declarations instead of keeping broad capabilities.
- Manifest parse errors, metadata mismatch errors, unsupported schema field
  types, and invented API imports are benchmark failures.

Warnings about an unregistered plugin-owned topic are acceptable for this
benchmark if the topic is intentionally local to the plugin and no shared
schema has been standardized yet. Shared framework topics must be declared and
schema-backed according to the normal plugin checker rules.
