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

Wrapper parsing should follow this order of preference:

1. Ask the tool for JSON, XML, or another documented machine-readable output
   mode.
2. Parse that output with a standard parser such as `json` or
   `xml.etree.ElementTree`.
3. Preserve the raw machine-readable output as an artifact when it is the
   parser source for a nontrivial normalization step.
4. Fall back to human text parsing only when the tool has no stable structured
   mode, and document that limitation in the wrapper tests or help text.

Parser failures are assessment evidence. They should create explicit
`tool.error` or equivalent diagnostic events and should not silently suppress
the tool result, fabricate normalized facts, or discard the raw output.

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

When a tool exits nonzero, produces no expected structured output, produces no
expected artifact files, or emits warnings with otherwise usable output, link
the resulting diagnostic event to the retained artifact whenever possible. The
operator should be able to move from `results` or `event tool.error` directly
to `artifact show <id>` or `artifact list ...`.

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

The minimum useful fixture set for a process wrapper is:

- a successful structured parse that emits normalized facts;
- malformed structured output that emits a parser `tool.error` and links raw
  output evidence;
- missing expected output that emits a `tool.error` and links process-output
  evidence when stdout/stderr exists;
- nonzero exit with partial stdout/stderr retained as artifact evidence;
- warnings or empty results that do not create false positive normalized
  findings.

## Runtime Behavior

Wrappers should:

- use argv lists and `shell=False`
- declare `framework.process.run` or narrower process capabilities
- declare produced topics in `emits`
- map portable facts into shared event schemas
- keep tool-native details in private topics or artifacts
- support practical `timeout`, `limit`, and target-scope controls
- surface parser failures as events or clear command failures, not silent drops
- avoid emitting normalized vulnerability/finding facts from incomplete parser
  state unless the payload clearly records the lower confidence and evidence

## Support Policy

Document the external tool versions used for fixtures. When upstream output
changes, add the new fixture before changing parser behavior. If a wrapper only
supports a subset of tool versions or modes, say that in the plugin help and
manifest notes.
