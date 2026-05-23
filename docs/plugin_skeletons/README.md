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
- Publish normalized findings with `finding.candidate` or `finding.confirmed`
  payloads built through `bywaf.findings.candidate_payload(...)`; do not invent
  unrelated finding keys.
- If code publishes `finding.candidate` or `finding.confirmed`, declare
  `db.write:finding.candidate` or `db.write:finding.confirmed` in both the
  decorator capabilities and `bywaf.plugin.toml`.
- Use `event finding.candidate` or `report` to inspect results; do not use a
  nonexistent `show finding.candidate` command.

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
