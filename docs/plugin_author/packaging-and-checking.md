# Plugin Packaging And Checking

How to load, package, validate, sign, and AI-check filesystem plugins.

## Contents

- [Loading and Packaging Plugins](#loading-and-packaging-plugins)
- [Why Manifests Matter](#why-manifests-matter)
- [AI-Assisted Plugin Development](#ai-assisted-plugin-development)
- [Standalone Plugin Checking](#standalone-plugin-checking)
- [Plugin Catalog Signing](#plugin-catalog-signing)

## Loading and Packaging Plugins

During development, plain plugin names resolve under:

```text
.bywaf/plugins
```

So:

```text
bywaf> plugin load=file_info --force
```

loads:

```text
.bywaf/plugins/file_info/plugin.py
```

Explicit paths also work:

```text
bywaf> plugin load=./scratch/file_info --force
bywaf> plugin load=~/bywaf-plugins/file_info --force
bywaf> pload ./scratch/file_info --force
```

Catalog placement is controlled by the loader or trusted catalog, not by plugin
code. A plugin declares what it provides, while Bywaf decides where that provider
appears in the user-facing catalog. In normal development, the catalog path is
derived from the plugin root-relative filesystem path. Local development loading
also supports an explicit `path=...` placement:

```text
bywaf> plugin load=./scratch/repo_tools path=http/repo_exposure --force
```

Treat `path=...` as an operator override for manual testing, not as metadata
accepted from untrusted plugin code. Signed catalog plugins use the catalog's
declared path and cannot be silently remapped by plugin code.

Add `--use` to switch the interactive variable context to the loaded commandlet
when the plugin exposes one commandlet. If it exposes multiple commandlets, use
`use=<commandlet>` so Bywaf does not guess:

```text
bywaf> pload ./scratch/file_info --force --use
bywaf> plugin load=./scratch/repo_tools --force use=git_expose_check
```

Filesystem plugin packages must include `plugin.py` and `bywaf.plugin.toml`.
The manifest is required so Bywaf has commandlet names, capabilities, secret
options, trigger rules, and plugin traits available as package metadata instead
of treating imports as discovery.

Filesystem plugins run with capability enforcement by default. During normal
use, undeclared calls to mediated APIs such as `context.output(...)`,
`context.process.run(...)`, `context.artifacts.write(...)`, or
`context.events.publish(...)` are denied after Bywaf records the missing
capability evidence. During local manifest development, an operator can
temporarily set `global.capabilities.mode=audit` to discover missing
declarations without blocking execution.

## Why Manifests Matter

The sidecar manifest is intentionally more than packaging metadata:

- **Enforceable contract:** commandlets cannot use capabilities, secret
  options, provider variables, or trigger rules they did not declare. The
  framework and checker can compare the Python plugin schema against the
  manifest and reject drift.
- **Static catalog metadata:** Bywaf can inspect plugin names, commandlets,
  roles, traits, capabilities, and trigger declarations without importing
  plugin Python code. This keeps catalog views, completion, and trust checks
  safer and faster.
- **Pre-load configuration surface:** declared commandlets and variables give
  the framework enough information to accept catalog variable values before
  the plugin is loaded, then apply those values when the commandlet becomes
  available.
- **Human and LLM guardrail:** plugin authors, AI assistants, and CI tooling get
  a second source of truth. `plugin_check` can catch missing capabilities,
  mismatched commandlets, undeclared provider-variable reads, and manifest/code
  inconsistencies before a plugin is trusted.

This is why Bywaf goes to the extra effort of keeping Python decorators and
sidecar TOML synchronized. Decorators define the runtime commandlet contract;
the manifest makes that contract reviewable, enforceable, and useful before
code import.

`--force` is required for REPL-loaded filesystem plugins unless a future
runtime catalog trust check verifies the plugin first. Filesystem plugins are
arbitrary local Python code, so forcing a load is an explicit operator
acknowledgement that every plugin trust check is being bypassed for reviewed
local code.

Startup plugin roots use the same policy. If you start Bywaf with
`--plugin-root` and `--plugin-config`, use `--allow-unsigned-plugins` for
unsigned development plugins:

```text
bywaf --plugin-root ~/.bywaf/plugins --plugin-config ~/.bywaf/plugins/plugins.toml --allow-unsigned-plugins
```

The plugin catalog builder uses the same filesystem entry layout as runtime
loading. A config entry such as `default_plugins = ["myplugin"]` describes
`~/.bywaf/plugins/myplugin/plugin.py` plus
`~/.bywaf/plugins/myplugin/bywaf.plugin.toml`.

Every plugin manifest should declare `[plugin].version`, for example
`version = "0.12.2"`. Use optional `requires_bywaf = ">=0.12.2"` when the plugin
depends on framework APIs or event-schema behavior introduced in a specific
Bywaf release. `plugin_check` fails missing plugin versions, and command-run
provenance records the plugin version and Bywaf version that produced each
step.

For reviewed external plugin trees, build and sign a catalog, then provide the
catalog and trusted public key at startup. Runtime verification checks the
catalog signature and the `plugin.py` / `bywaf.plugin.toml` hashes before
loading code:

```text
bywaf --plugin-root ~/.bywaf/plugins \
  --plugin-config ~/.bywaf/plugins/plugins.toml \
  --plugin-catalog ~/.bywaf/plugins/plugin-catalog.signed.json \
  --plugin-catalog-key ~/.bywaf/plugins/plugin-catalog.pub.pem
```

Runtime catalog trust decisions are audited with
`plugin.catalog.verified`, `plugin.catalog.rejected`,
`plugin.catalog.entry.verified`, and `plugin.catalog.entry.rejected`.

Plugin manifest signatures sign a digest of canonical parsed values, not raw
TOML bytes. Comments, whitespace, and formatting can change freely without
disturbing the signature; changes to the actual declarative values change the
digest. Lists in framework-managed config are treated as unordered sets by
policy, including capability lists, commandlet rows, trigger rows, roles,
excluded commandlets, and key lists.

Manifest metadata uses strict TOML types. Strings must be strings, booleans
must be `true` or `false`, and string lists must contain only strings. Bywaf
rejects malformed trust metadata instead of converting values such as
`"false"` or `123` into plausible catalog entries.

`--allow-missing-plugin-keys` and `--allow-mismatched-plugin-keys` are narrower
developer bypasses for future signed external plugin catalogs when the trusted
verification key is absent or does not match the plugin signature.
`--plugin-manifest-key` supplies the trusted public key for signed
`bywaf.plugin.toml` files. `--allow-unsigned-plugin-manifests` is the narrow
development bypass for unsigned manifests. The legacy
`--force-plugins` startup flag is a hidden compatibility alias for
`--allow-untrusted-plugins`, a command-line argument that states the full
tradeoff directly: load the plugin even though Bywaf cannot verify its
signature, signing key, or key match.

Official Bywaf releases reserve `bywaf/keys/plugin-manifest.pub.pem` for the
framework public verification key. Only public keys belong in that package;
private manifest-signing keys are maintainer release material and must stay
outside the repository and built packages. Operators can use
`--plugin-manifest-key` to trust a different public key for local or
third-party plugin ecosystems.

Official manifest-signing keys rotate annually with a 60-day staggered
transition. Bywaf publishes the next public verification key before it is used
for signing, temporarily trusts both the current and next public keys during
the transition window, starts signing new manifests with the next private key
on the rotation date, re-signs official plugin manifests with that key for the
rotation release, and retires the old public key after the transition window.
Retired keys are no longer part of the official trusted key set for normal
annual rotation. Revocation is reserved for suspected compromise or emergency
distrust and removes the affected key from trust immediately.

Maintainer storage controls for private signing keys are recorded in
`KEY_MANAGEMENT.md`. In short: private keys stay encrypted, outside the
repository and package tree, with permissions no broader than `0600`; public
verification keys can be committed and packaged.

Bundled plugins live under `bywaf/plugins/` and are loaded from
`bywaf/plugins/plugins.toml`. To make a bundled commandlet load automatically,
add its dotted module path to `default_plugins` and add or update the matching
sidecar manifest, for example `bywaf/plugins/http/nikto.plugin.toml`.

## AI-Assisted Plugin Development

Use the dedicated [LLM-Assisted Plugin Authoring](llm-assisted-authoring.md)
workflow. In short: generate into a scratch directory, run
`scripts/plugin_check.py --strict-inference --llm-feedback`, paste the checker
output back to the assistant, and repeat until the plugin passes. The checker is
the source of truth; assistant output is only a proposal.

## Standalone Plugin Checking

Development plugin validation is done outside the Bywaf interpreter. Use the
standalone checker before loading a filesystem plugin with development trust
bypasses:

```bash
python3 scripts/plugin_check.py path/to/plugin-dir
python3 scripts/plugin_check.py path/to/plugin-dir --strict-inference
python3 scripts/plugin_check.py path/to/plugin-dir --strict-inference --llm-feedback
python3 scripts/plugin_check.py path/to/plugin-dir --graph
python3 scripts/plugin_check.py path/to/plugin-dir --manifest-key manifest-signing.pub.pem --verify
python3 scripts/plugin_check.py path/to/plugin-dir --json
python3 scripts/plugin_check.py path/to/plugin.zip --temp-checkout --strict-inference --llm-feedback
python3 scripts/plugin_check.py --all
python3 scripts/plugin_check.py --all --strict-inference
python3 scripts/plugin_check.py --all --graph
python3 scripts/plugin_graph.py --topic port.open
python3 scripts/plugin_graph.py --provider http.http_probe
```

`plugin_check` is a schema verifier, not just a style linter. Its strict
checks intentionally fail plugins whose Python metadata, manifest, and common
runtime patterns disagree. In particular, it checks:

- unknown or invented manifest keys
- decorator metadata and runtime parser alignment
- manifest/decorator capability synchronization
- manifest/decorator database action policy synchronization
- manifest/decorator `consumes` and `emits` metadata when declared
- plugin-level `requires_schemas` and `requires_plugins` dependency metadata
- shared event topic declarations for framework-owned and plugin-owned schemas
- literal shared event payloads when static analysis can read them
- secret option declarations
- trigger declarations
- normalized finding payload helper usage
- cancellability patterns for long-running loops
- JSON-serializable yielded event payloads
- obvious direct network/process/filesystem APIs that should be declared or
  mediated by the framework

Use `--graph` when you need relationship context rather than only pass/fail
validation. For a filesystem plugin, `plugin_check --graph` reports the
plugin's declared schemas, consumed topics, emitted topics, database topic
access, and known bundled producers or consumers for those topics. This is
advisory context: declaring `consumes = ["port.open"]` means the plugin can
consume that topic when events are available; it does not automatically load a
producer plugin. For bundled provider inspection, `scripts/plugin_graph.py`
prints the pre-import manifest graph directly, for example known producers and
consumers of `port.open` or the relationships for `http.http_probe`.

The checker does not make plugin code sandboxed or inherently safe. Native and
library-backed plugins are still Python code. Treat a passing check as
"schema checked and ready for review," not as a security proof.

Use `--all` as a maintainer check for the bundled plugin suite. It validates
every provider listed in `bywaf.plugins/plugins.toml` and fails if any bundled
manifest drifts from its Python commandlet metadata, parser contract, shared
event declarations, or trigger declarations. Use `--all --strict-inference`
before release-style batches to also fail missing AST-inferred capability
declarations across the bundled suite.

The input may be an unpacked plugin directory or a `.zip` containing one plugin
directory. Use `--temp-checkout` for LLM-generated or review submissions: the
checker copies the current Bywaf tree to a temporary checkout, safely unpacks or
copies the submitted plugin into that checkout, and reruns validation there with
the same flags. This catches packaging and import assumptions without changing
the working tree.

The checker requires `plugin.py` and `bywaf.plugin.toml`, parses strict manifest
metadata, registers plugin-owned `[[event_schemas]]` declarations for checking,
imports the plugin factory, and verifies that declared commandlets,
capabilities, database action flags, shared event declarations, secret options,
trigger specs, and declared parser options/arguments match the code. It also
runs a lightweight AST pass over plugin source and reports inferred
capabilities, missing inferred declarations, unused declarations, and warnings
for direct network, process, and filesystem APIs that bypass framework
mediation. It also warns when runtime artifact-store access omits explicit
`read_access=True` or `write_access=True`, since that usually means artifact
capability auditing would be ambiguous.
Inference is advisory by default; `--strict-inference` turns missing inferred
capabilities into a failed check. When `--manifest-key` is supplied, it also
verifies the manifest signature.

`--llm-feedback` emits concise, pasteable correction text for AI-assisted
plugin development. Use it when an external assistant generated a plugin:

```bash
python3 scripts/plugin_check.py /tmp/llm-plugin --strict-inference --llm-feedback
```

Paste the full output back into the assistant and ask it to regenerate the
complete plugin directory. The feedback mode calls out common authoring
mistakes such as `@argument(..., nargs=...)`, decorators placed on `plugin()`,
unsupported `candidate_payload(...)` or `confirmed_payload(...)` keyword names,
and `context.is_cancelled()`. Manifest blockers are also rendered as concrete
paste-back fixes, including missing required fields such as
`[plugin].version`.

The checked-in skeletons under `../plugin_skeletons/` are validated by the
test suite with this checker. If a skeleton no longer loads or its manifest
drifts from the code, CI should fail before plugin authors copy the broken
pattern.

Generate a starter manifest from Python metadata:

```bash
python3 -m bywaf.tools.plugin_manifest path/to/plugin-dir/plugin.py
python3 -m bywaf.tools.plugin_manifest path/to/plugin-dir/plugin.py --infer-capabilities
```

The generator emits commandlet rows, declared capabilities, `consumes` and
`emits` topics, secret options, provider-owned trigger specs, and can render
plugin-owned event schemas when tooling passes them in. With
`--infer-capabilities`, AST-inferred
capabilities are merged into the manifest only when the plugin exposes exactly
one commandlet; multi-commandlet plugins still need the author to assign
inferred capabilities to the right commandlet manually.

Sign a plugin manifest outside the Bywaf interpreter:

```bash
python3 scripts/plugin_manifest_sign.py \
  --manifest path/to/plugin-dir/bywaf.plugin.toml \
  --private manifest-signing.pem \
  --in-place
```

## Plugin Catalog Signing

Bywaf keeps runtime plugin loading separate from maintainer release tooling. The
maintainer-side catalog helper builds a reviewed catalog from bundled plugin
source files and sidecar manifests, records SHA-256 hashes, and can sign that
catalog with an encrypted Ed25519 key:

```bash
python3 scripts/plugin_catalog.py build --output dist/plugin-catalog.json
python3 scripts/plugin_catalog.py generate-key \
  --private maintainer-plugin-signing.pem \
  --public maintainer-plugin-signing.pub.pem
python3 scripts/plugin_catalog.py sign \
  --catalog dist/plugin-catalog.json \
  --private maintainer-plugin-signing.pem \
  --signer "Bywaf maintainer" \
  --output dist/plugin-catalog.signed.json
python3 scripts/plugin_catalog.py verify \
  --catalog dist/plugin-catalog.signed.json \
  --public maintainer-plugin-signing.pub.pem \
  --check-tree
```

`verify` checks the catalog signature. `--check-tree` additionally checks that
the current plugin modules and sidecar manifests still match the hashes and
metadata in the signed catalog. This is the beginning of plugin chain-of-custody
support; runtime trust prompts, revocation policy, and external plugin package
distribution are still design items.
