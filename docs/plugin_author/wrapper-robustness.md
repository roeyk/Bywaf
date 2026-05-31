# Wrapper Robustness

External-tool wrappers are useful, but they are fragile unless their parser and
evidence contracts are explicit.

## Policy

Prefer structured upstream output when the tool supports it:

- XML over human tables
- JSON over free-form text
- machine-readable logs over terminal progress output

Human-readable output may still be preserved as evidence, but normalized Bywaf
events should come from the most stable machine-readable source available.

## Evidence Retention

Wrappers should keep enough raw evidence to debug parser drift:

- `process.run` or equivalent stdout/stderr provenance
- attached raw output artifacts for every blocking `context.process.run(...)`
- tool argv, return code, timeout state, and stderr summary
- parser warning/error events when normalization is incomplete

Do not make normalized events the only copy of an external tool's result when
the parser is nontrivial. Bywaf's blocking process helper stores a redacted
stdout/stderr transcript artifact automatically; wrapper plugins still need to
declare `artifact.write`.

## Fixture Tests

Every major wrapper parser should have fixtures for:

- normal findings
- empty output
- warnings with otherwise usable output
- errors and nonzero exit codes
- partial output
- changed or unknown tool versions
- duplicate records
- fields with spaces, punctuation, or missing optional values

Tests should assert emitted Bywaf events, attached artifacts where relevant,
and operator-facing summaries. Avoid live internet dependencies in parser
tests.

## Runtime Behavior

Wrappers should:

- use argv lists and `shell=False`
- declare `framework.process.run` or narrower process capabilities
- declare produced topics in `emits`
- map portable facts into shared event schemas
- keep tool-native details in private topics or artifacts
- support practical `timeout`, `limit`, and target-scope controls
- surface parser failures as events or clear command failures, not silent drops

## Support Policy

Document the external tool versions used for fixtures. When upstream output
changes, add the new fixture before changing parser behavior. If a wrapper only
supports a subset of tool versions or modes, say that in the plugin help and
manifest notes.
