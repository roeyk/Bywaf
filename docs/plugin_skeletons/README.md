# Plugin Skeletons

These skeletons are copyable starting points for Bywaf plugins. They are
intentionally comment-heavy so human developers and AI assistants can keep the
framework boundary straight.

Treat each skeleton as a fill-in template, not only as a reference example.
Copy the closest directory, rename the commandlet/package, and replace the
commented sections that say where to place detection, verification, parsing,
or finding-packaging code. Prefer filling in the existing functions/classes
over inventing a new plugin layout from scratch.

For the smallest native one-commandlet plugin, prefer the scaffold command:

```bash
python3 scripts/plugin_new.py my_probe --output /tmp/my_probe
```

Use `--bundled <family>` when the same small native commandlet should ship
under `bywaf/plugins/...`:

```bash
python3 scripts/plugin_new.py my_probe --bundled http
```

The scaffold is not a replacement for skeletons that model vulnerability
finding packaging, library-backed integrations, wrapped binaries, or
service/provider behavior.

Use these skeleton directories when the plugin needs a richer shape, such as
vulnerability finding packaging, a third-party library, an external process, or
a provider-owned service trigger.

LLM Guardrails:

- For ordinary commandlets, prefer a manifest-backed bare `@commandlet`
  function that receives `(context, cfg, input_events)`. This is the default
  authoring path unless the commandlet needs advanced hooks.
- For advanced commandlets, decorate the `CommandletBase` class with
  `@commandlet`, `@argument`, and `@option`. Do not decorate the `plugin()`
  factory in either style.
- In these skeletons, keep the registration object in `plugin.py`. `command.py`
  should provide orchestration functions, not registration.
- Publish normalized findings with `finding.candidate` payloads built through
  `bywaf.finding.candidate_payload(...)` or `finding.confirmed` payloads built
  through `bywaf.finding.confirmed_payload(...)`; do not invent unrelated
  finding keys.
- If code publishes `finding.candidate` or `finding.confirmed`, declare
  `db.write:finding.candidate` or `db.write:finding.confirmed` in both the
  decorator capabilities and `bywaf.plugin.toml`.
- `confidence`, `severity`, and `status` are separate. Use confidence labels
  like `"low"`, `"medium"`, or `"high"`; do not put `"confirmed"` in
  `confidence`.
- Finding classes use lowercase dotted Bywaf names such as
  `web.header.missing_hsts`; external ids such as CVE, CWE, OWASP, GHSA, and
  vendor advisories go in `identifiers`.
- Boolean-style manifest options should use `type = "bool"` and an explicit
  default such as `default = "false"`. Boolean-style class `@option` metadata
  must include an explicit string default and choices, such as
  `@option("confirm", "perform confirmation", "false", ("true", "false"))`.
  Put `action="store_true"` or other argparse mechanics in runtime parsing, not
  in metadata.
- Yielded event payloads must be JSON-serializable. Do not yield dataclass
  instances, connection objects, exceptions, or other Python objects directly.
- Only publish `finding.confirmed` when `--confirm` was requested or when the
  check performed a genuinely confirmatory proof. Otherwise publish
  `finding.candidate`.
- Use `event finding.candidate` or `report` to inspect results; do not use a
  nonexistent `show finding.candidate` command.

Exact finding helper shape:

```python
from bywaf.finding import candidate_payload, confirmed_payload, subject_value

payload = candidate_payload(
    title="Missing Strict Transport Security",
    finding_class="web.header.missing_hsts",
    severity="medium",
    confidence="medium",
    finding_scope="web_origin",
    target={"scheme": "https", "host": "example.test", "port": "443", "path": "/"},
    identifiers={"cwe": ["CWE-319"]},
    evidence="https://example.test/ did not return Strict-Transport-Security.",
    recommendation="Enable HSTS after confirming HTTPS coverage.",
    source={"tool": "my_plugin", "topic": "finding.candidate"},
)

confirmed = confirmed_payload(
    title="Exposed Git repository configuration",
    finding_class="web.exposure.git_config",
    severity="high",
    confidence="high",
    finding_scope="web_route",
    target={"scheme": "https", "host": "example.test", "port": "443", "path": "/.git/config"},
    evidence="The endpoint returned Git config content.",
    recommendation="Block access to .git paths and rotate exposed credentials.",
    source={"tool": "my_plugin", "topic": "finding.confirmed"},
)
```

Use `subject_value(...)` when an output value's meaning is not obvious from the
field name. For example, use `subject_value("username", "admin")` for a login
name, or `subject_value("explanation", text)` for scanner prose that explains a
vulnerability. Subjects describe what a value is about; reporters map subjects
to colors and labels.

Use the smallest skeleton that fits:

| Skeleton | Use when |
| --- | --- |
| `native_minimal` | One small native commandlet is enough. |
| `native_vulnerability` | A vulnerability or CVE plugin needs detection, confirmation, finding packaging, and tests. |
| `library_backed` | The plugin imports a third-party Python library in-process. |
| `library_backed_vulnerability` | A vulnerability or CVE plugin uses a third-party Python library to collect evidence. |
| `process_wrapped` | The plugin invokes an external binary/tool and parses its output. |
| `process_wrapped_vulnerability` | A vulnerability or CVE plugin wraps an external tool and promotes parsed results into findings. |
| `service_trigger_provider` | The plugin provides a long-running service started by provider-owned triggers. |

If the task fits the scaffold scope, use `scripts/plugin_new.py` before copying
`native_minimal`. Keep `native_minimal` as the copyable teaching reference and
as the fallback when the scaffold does not cover the needed layout.

The split is guidance, not a loader requirement. Bywaf still loads any valid
plugin package with `plugin.py`, `plugin()`, and a matching `bywaf.plugin.toml`.
The skeletons exist to make the preferred structure easy to copy, especially
for vulnerability-detection plugins and AI-assisted plugin generation.
Keep required manifest fields from the copied skeleton. In particular,
filesystem plugin manifests must include a non-empty `[plugin].version`; add
`requires_bywaf` when the plugin needs a minimum Bywaf API version.

Before loading or sharing a generated plugin, run:

```bash
python3 scripts/plugin_check.py path/to/plugin-dir --strict-inference
python3 scripts/plugin_check.py path/to/plugin-dir --strict-inference --llm-feedback
```

Use `--llm-feedback` when working with a chat-based assistant. Paste the full
checker output back into the assistant and ask it to regenerate the complete
plugin directory. The checker catches common LLM drift such as unsupported
decorator keywords, decorators on `plugin()`, nonexistent finding helpers,
manifest/capability mismatches, and unsupported context APIs.

These skeleton directories are themselves validated by Bywaf tests. Treat that
as part of their contract: if a skeleton stops passing `scripts/plugin_check.py`,
fix the skeleton before copying it into a real plugin.
