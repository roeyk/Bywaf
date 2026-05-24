# Plugin Packaging And Checking

How to load, package, validate, sign, and AI-check filesystem plugins.

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

Add `--use` to switch the interactive variable context to the loaded commandlet
when the plugin exposes one commandlet. If it exposes multiple commandlets, use
`--use=<commandlet>` so Bywaf does not guess:

```text
bywaf> pload ./scratch/file_info --force --use
bywaf> plugin load=./scratch/repo_tools --force --use=git_expose_check
```

Filesystem plugin packages must include `plugin.py` and `bywaf.plugin.toml`.
The manifest is required so Bywaf has commandlet names, capabilities, secret
options, trigger rules, and plugin traits available as package metadata instead
of treating imports as discovery.

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
python3 scripts/plugin_check.py path/to/plugin-dir --manifest-key manifest-signing.pub.pem --verify
python3 scripts/plugin_check.py path/to/plugin-dir --json
```

The checker requires `plugin.py` and `bywaf.plugin.toml`, parses strict manifest
metadata, imports the plugin factory, and verifies that declared commandlets,
capabilities, secret options, and trigger specs match the code. It also runs a
lightweight AST pass over plugin source and reports inferred capabilities,
missing inferred declarations, unused declarations, and warnings for direct
network, process, and filesystem APIs that bypass framework mediation.
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
unsupported `candidate_payload(...)` keyword names, nonexistent
`confirmed_payload(...)`, and `context.is_cancelled()`.

The checked-in skeletons under `../plugin_skeletons/` are validated by the
test suite with this checker. If a skeleton no longer loads or its manifest
drifts from the code, CI should fail before plugin authors copy the broken
pattern.

Generate a starter manifest from Python metadata:

```bash
python3 -m bywaf.tools.plugin_manifest path/to/plugin-dir/plugin.py
python3 -m bywaf.tools.plugin_manifest path/to/plugin-dir/plugin.py --infer-capabilities
```

The generator emits commandlet rows, declared capabilities, secret options, and
provider-owned trigger specs. With `--infer-capabilities`, AST-inferred
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
