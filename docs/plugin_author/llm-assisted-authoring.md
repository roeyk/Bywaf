# LLM-Assisted Plugin Authoring

AI assistants can be useful for drafting plugin ideas, detection heuristics,
test cases, and first-pass code. They are not the authority on the Bywaf API.
Treat assistant output as a proposal until it passes the plugin conformance
checker.

## Contents

- [The Loop](#the-loop)
- [Good LLM Tasks](#good-llm-tasks)
- [High-Risk LLM Tasks](#high-risk-llm-tasks)
- [Prompt Template](#prompt-template)
- [Feedback Template](#feedback-template)

## The Loop

Use this loop for AI-generated plugins:

1. Decide whether the task fits the scaffold scope. Use
   `scripts/plugin_new.py` for a small native plugin with one commandlet, one
   main input, one plugin-owned event topic, no third-party Python dependency,
   no wrapped binary, no background service, and no complex finding-packaging
   split. Use `--bundled <family>` only when the requested plugin should ship
   under `bywaf/plugins/...`.
2. If the task does not fit that scope, start from the closest checked-in
   skeleton under `../plugin_skeletons/`.
3. Ask the assistant to fill in the scaffold or skeleton, not invent a new
   layout.
4. Require a complete plugin directory, including `plugin.py`,
   `bywaf.plugin.toml`, and any split files such as `command.py`, `detect.py`,
   `findings.py`, and `models.py`.
5. Put the generated plugin in a scratch directory outside the repository, for
   example `/tmp/bywaf-llm-plugins/git_expose_check`.
6. Run the post-generation validation gate:

   ```bash
   python3 scripts/plugin_check.py /tmp/bywaf-llm-plugins/git_expose_check.zip \
     --temp-checkout --strict-inference --llm-feedback
   python3 scripts/plugin_check.py /tmp/bywaf-llm-plugins/git_expose_check \
     --strict-inference --llm-feedback
   ```

7. Paste the full checker output back into the assistant and ask it to
   regenerate the complete plugin directory.
8. Repeat until the checker passes.
9. Review the detection logic manually, add focused tests, and only then copy
   the plugin into a real plugin root.

This is a conformance loop, not a conversation about confidence. If the
assistant says the plugin is correct but the checker fails, the checker wins.

## Good LLM Tasks

Good tasks for an assistant:

- propose plugin ideas and target edge cases
- draft pure `detect.py` logic that can be tested without Bywaf
- draft recommendation and evidence wording
- identify likely capabilities and plugin type
- suggest focused test cases

## High-Risk LLM Tasks

Do not trust assistant output without the checker for:

- exact decorator signatures
- manifest/decorator capability synchronization
- finding payload helper arguments
- Bywaf command examples
- package layout and relative imports
- boolean-style option metadata

## Prompt Template

Use a prompt like this:

```text
Read the current Bywaf plugin author docs. If this task fits scaffold scope,
use scripts/plugin_new.py to create the initial plugin directory and then edit
only what is necessary. Otherwise, use the closest plugin skeleton and explain
why the scaffold does not fit.
Use only the current commandlet API. Do not use Veil modules, Metasploit
modules, info dictionaries, modules/ layout, or run/exploit entrypoints.
Create a complete filesystem plugin directory for <plugin-name>.

Rules:
- Start from the scaffold or documented skeleton; do not invent a new layout.
- Include plugin.py, bywaf.plugin.toml, and any split files required by the
  scaffold or skeleton.
- For small commandlets, prefer a manifest-backed @commandlet function in
  plugin.py that receives (context, cfg, input_events), not decorators on
  plugin().
- For advanced class-based commandlets, put @commandlet, @argument, and @option
  on the CommandletBase class in plugin.py, not on plugin().
- Keep manifest/decorator metadata and runtime behavior separate.
- For boolean-style manifest options, use type = "bool" and an explicit default
  such as default = "false". For class @option metadata, use explicit string
  defaults and choices such as @option("confirm", "perform confirmation",
  "false", ("true", "false")).
- Use bywaf.finding.candidate_payload(...) for normalized candidate findings.
- Use bywaf.finding.confirmed_payload(...) only when the plugin has direct proof.
- Yield only JSON-serializable dictionaries.
- Include usage examples using real Bywaf commands.

Output only the complete plugin directory tree and file contents.
```

## Feedback Template

When the checker fails, paste the complete `--llm-feedback` output back to the
assistant with this instruction:

```text
Apply this Bywaf plugin checker feedback exactly. Then regenerate the complete
plugin directory. Do not provide only a patch; output every file again.
```

Do not summarize or soften checker output. The point is to make the assistant
conform to the tool, not to negotiate the API.
