# Writing Bywaf Plugins

This is the entry point for Bywaf plugin authors. The detailed material is split
into focused pages so each page has one job and can be read independently.

## Contents

- [What To Do First](#what-to-do-first)
- [Current API At A Glance](#current-api-at-a-glance)
- [Choose A Starting Point](#choose-a-starting-point)
- [Plugin Shape](#plugin-shape)
- [Find It At A Glance](#find-it-at-a-glance)

## What To Do First

For most implementors, do this:

1. [Plugin Fundamentals](fundamentals.md)
2. Copy the closest [Plugin Skeleton](../plugin_skeletons/README.md)
3. Fill in the existing files instead of inventing a new layout
4. Run:

   ```bash
   python3 scripts/plugin_check.py path/to/plugin-dir --strict-inference
   ```

5. Add focused tests for `detect.py`, `findings.py`, and the commandlet path

If the checker fails, fix the checker output first. Do not load or package the
plugin until it passes.

If you are writing a vulnerability or CVE check, also read:

- [Vulnerability Plugin Guide](vulnerability-plugins.md)
- [Plugin Skeletons](../plugin_skeletons/README.md)

If you are using an AI assistant to draft a plugin, use the checker loop in
[LLM-Assisted Plugin Authoring](llm-assisted-authoring.md). The checker is the
source of truth; assistant output is only a proposal until it passes
`scripts/plugin_check.py --strict-inference`.

## Current API At A Glance

Bywaf plugins provide commandlets. They do not use Veil-style modules,
Metasploit-style `info` dictionaries, or `run/exploit` entrypoints.

```text
plugin.py          decorated CommandletBase class plus plugin() factory
command.py         runtime parsing, event iteration, context interaction
detect.py          pure detection/protocol logic, testable without Bywaf
findings.py        normalized finding payloads via bywaf.finding helpers
models.py          plugin-local domain objects
bywaf.plugin.toml  sidecar manifest contract for capabilities and traits
```

The current plugin API centers on:

- `@commandlet`, `@argument`, and `@option` metadata
- `CommandletBase`
- `CommandContext`
- `run(self, context, args, input_events)`
- yielded JSON-serializable dictionaries for normal event output
- `def plugin() -> Commandlet`
- `bywaf.plugin.toml`

Compatibility note: if an external answer suggests `BaseCommandlet`, an `info`
dict, a `modules/` directory API, or a `run(self, target, args)` method, it is
not following the current Bywaf plugin contract.

## Choose A Starting Point

| Goal | Start with | Then read |
| --- | --- | --- |
| Small one-file commandlet | `native_minimal` skeleton | [Plugin Fundamentals](fundamentals.md) |
| Third-party Python library plugin | `library_backed` skeleton | [Plugin Fundamentals](fundamentals.md) |
| External binary wrapper | `process_wrapped` skeleton | [Commandlet API Reference](commandlet-api.md#framework-requests-and-audit-events) |
| Vulnerability or CVE detector | `native_vulnerability`, `library_backed_vulnerability`, or `process_wrapped_vulnerability` | [Vulnerability Plugin Guide](vulnerability-plugins.md) |
| Long-running service with provider triggers | `service_trigger_provider` skeleton | [Plugin Packaging And Checking](packaging-and-checking.md) |
| AI-generated plugin draft | closest skeleton in a scratch directory | [LLM-Assisted Plugin Authoring](llm-assisted-authoring.md) |

## Plugin Shape

Bywaf plugins provide commandlets. A commandlet is a small class with:

- a `CommandSpec`, usually declared with `@commandlet`, `@argument`, and `@option`
- a `run()` method, which performs the work
- a `plugin()` factory function, which returns the commandlet instance

Commandlets can publish events by yielding dictionaries. The runner inserts
those dictionaries into SQLite under the first topic listed in `spec.emits`.

## Find It At A Glance

| Need | Go to |
| --- | --- |
| Current decorator API | [Plugin Fundamentals](fundamentals.md#current-api-not-generic-plugin-patterns) |
| `@argument` vs `@option` | [Plugin Fundamentals](fundamentals.md#defining-inputs-arguments-vs-options) |
| Full tiny plugin example | [Plugin Fundamentals](fundamentals.md#complete-external-plugin-example) |
| `CommandSpec` fields | [Commandlet API Reference](commandlet-api.md#commandspec-fields) |
| Parsing runtime args | [Commandlet API Reference](commandlet-api.md#parsing-arguments) |
| Publishing or consuming events | [Commandlet API Reference](commandlet-api.md#publishing-events) |
| Shared event payload contracts | [Shared Event Contracts](event-contracts.md) |
| Runtime context APIs | [Commandlet API Reference](commandlet-api.md#runtime-context) |
| Output subjects and theme styling | [Output Subjects And Theme Styles](output-subjects-and-styles.md) |
| Vulnerability plugin file split | [Vulnerability Plugin Guide](vulnerability-plugins.md#vulnerability-detection-plugin-layout) |
| Finding payload helpers | [Vulnerability Plugin Guide](vulnerability-plugins.md#findingspy) |
| Loading, packaging, and checker | [Plugin Packaging And Checking](packaging-and-checking.md) |
| LLM-assisted plugin loop | [LLM-Assisted Plugin Authoring](llm-assisted-authoring.md) |
| Testing expectations | [Plugin Testing And Guidelines](testing-and-guidelines.md) |
| Copyable skeletons | [Plugin Skeletons](../plugin_skeletons/README.md) |
