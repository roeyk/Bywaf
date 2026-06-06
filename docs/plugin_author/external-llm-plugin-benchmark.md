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

The plugin must:
- provide one commandlet named http_title;
- accept one required URL argument;
- use the current Bywaf commandlet API only;
- fetch http:// or https:// URLs using the Python standard library;
- use a bounded timeout;
- extract the HTML <title> text when present;
- emit one JSON-serializable event on topic http.title;
- declare the matching capabilities, emitted topic, argument, plugin-owned
  event schema, and database action policy in bywaf.plugin.toml;
- include focused tests that do not require external network access;
- include the exact plugin_check command that should pass.

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

Warnings about an unregistered plugin-owned topic are acceptable for this
benchmark if the topic is intentionally local to the plugin and no shared
schema has been standardized yet. Shared framework topics must be declared and
schema-backed according to the normal plugin checker rules.
