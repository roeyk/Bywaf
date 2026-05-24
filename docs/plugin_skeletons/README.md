# Plugin Skeletons

These skeletons are copyable starting points for Bywaf plugins. They are
intentionally comment-heavy so human developers and AI assistants can keep the
framework boundary straight.

Treat each skeleton as a fill-in template, not only as a reference example.
Copy the closest directory, rename the commandlet/package, and replace the
commented sections that say where to place detection, verification, parsing,
or finding-packaging code. Prefer filling in the existing functions/classes
over inventing a new plugin layout from scratch.

LLM Guardrails:

- Decorate the `CommandletBase` class with `@commandlet`, `@argument`, and
  `@option`; do not decorate the `plugin()` factory.
- In these skeletons, keep the decorated commandlet class in `plugin.py`.
  `command.py` should provide orchestration functions, not registration.
- Publish normalized findings with `finding.candidate` or `finding.confirmed`
  payloads built through `bywaf.findings.candidate_payload(...)`; do not invent
  unrelated finding keys.
- There is no `bywaf.findings.confirmed_payload(...)` helper. For confirmed
  findings, call `candidate_payload(...)` and then set `payload["status"] =
  "confirmed"`, as shown in the skeleton.
- If code publishes `finding.candidate` or `finding.confirmed`, declare
  `db.write:finding.candidate` or `db.write:finding.confirmed` in both the
  decorator capabilities and `bywaf.plugin.toml`.
- `confidence`, `severity`, and `status` are separate. Use confidence labels
  like `"low"`, `"medium"`, or `"high"`; do not put `"confirmed"` in
  `confidence`.
- Boolean-style `@option` metadata must include an explicit string default and
  choices, such as `@option("confirm", "perform confirmation", "false",
  ("true", "false"))`. Put `action="store_true"` or other argparse mechanics in
  runtime parsing, not in the decorator.
- Yielded event payloads must be JSON-serializable. Do not yield dataclass
  instances, connection objects, exceptions, or other Python objects directly.
- Only publish `finding.confirmed` when `--confirm` was requested or when the
  check performed a genuinely confirmatory proof. Otherwise publish
  `finding.candidate`.
- Use `event finding.candidate` or `report` to inspect results; do not use a
  nonexistent `show finding.candidate` command.

Exact finding helper shape:

```python
from bywaf.findings import candidate_payload

payload = candidate_payload(
    title="Missing Strict Transport Security",
    finding_class="missing-hsts",
    severity="medium",
    confidence="medium",
    target={"scheme": "https", "host": "example.test", "port": "443", "path": "/"},
    identifiers={"cwe": ["CWE-319"]},
    evidence="https://example.test/ did not return Strict-Transport-Security.",
    recommendation="Enable HSTS after confirming HTTPS coverage.",
    source={"tool": "my_plugin", "topic": "finding.candidate"},
)
```

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

The split is guidance, not a loader requirement. Bywaf still loads any valid
plugin package with `plugin.py`, `plugin()`, and a matching `bywaf.plugin.toml`.
The skeletons exist to make the preferred structure easy to copy, especially
for vulnerability-detection plugins and AI-assisted plugin generation.

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
