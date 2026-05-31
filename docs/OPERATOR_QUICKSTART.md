# Operator Quickstart

This is the first ten minutes with Bywaf. It assumes you are running Bywaf on
systems and networks where you have explicit authorization.

## Start

From a development checkout:

```bash
python3 -m bywaf
```

From an installed package:

```bash
bywaf
```

Create a fresh project database when you want a clean run:

```text
bywaf> db new
```

## Find Commands

List commandlets and inspect help:

```text
bywaf> cmds
bywaf> help hostscanner
bywaf> help portscanner
bywaf> help report
```

Use tab completion for command names, selectors, and manifest-declared options.

## Set Variables

Most commandlets expose variables that can be set once and reused:

```text
bywaf> use network/portscanner
bywaf> set port=22,80,443
bywaf> set arguments=-sT
```

Use fully qualified names when you are not focused on a provider:

```text
bywaf> set network/portscanner.port=22,80,443
```

Secret values should use secret-aware inputs and plugin secret options where a
plugin supports them. Do not put passwords directly into reusable scripts or
notes.

## Run A Safe Local Flow

Start with localhost or a lab host:

```text
bywaf> hostscanner 127.0.0.1 | portscanner
```

For a small authorized subnet:

```text
bywaf> hostscanner host=192.168.50.0/24 | portscanner
```

For web assessment data:

```text
bywaf> hostscanner host=192.168.50.0/24 | portscanner | http_probe | webfin
```

## Inspect What Happened

Runtime views show work that changed project state:

```text
bywaf> job
bywaf> pipeline
bywaf> step
```

Inventory views answer operator questions without requiring you to remember the
producer commandlet:

```text
bywaf> hosts
bywaf> ports
bywaf> web
bywaf> services
```

`results` shows the useful result view for the latest relevant producer:

```text
bywaf> results
```

Scope a view when needed:

```text
bywaf> ports job=3
bywaf> results pipeline=7
bywaf> event step=12
```

If a scope has evidence files, `results`, `job <id>`, `pipeline <id>`, and
`step <id>` show compact artifact references and the matching `artifact list
...` command. Use `artifact show <id>` when you want one artifact's provenance,
hash, and next inspection commands.

## Review Findings

`report` is the finding inbox and scoped finding viewer:

```text
bywaf> report
bywaf> report --last
bywaf> report sort=host
bywaf> report sort=finding
```

When a finding is real, record the decision:

```text
bywaf> finding confirm 1 note=validated manually
bywaf> report confirm 1 note=validated manually
```

Use `accept` for reviewed-but-not-proofed issues, `defer` for later review, and
`reject` for false positives.

## Audit And Artifacts

Audit evidence is stored as events:

```text
bywaf> event plugin.capability.used
bywaf> audit list capabilities
```

Artifacts are tracked separately but linked back to runtime provenance:

```text
bywaf> artifact list
bywaf> artifact list step=12
bywaf> artifact show 1
bywaf> artifact verify
```

## Stop Or Control Work

Use high-level controls first:

```text
bywaf> pause job=3
bywaf> resume job=3
bywaf> stop pipeline=7
bywaf> end step=12
```

`signal` is the lower-level live-control escape hatch for plugin-specific
messages such as pruning targets or changing verbosity.

## Trust Model

Bundled plugins are curated with manifests, capabilities, database-action
metadata, tests, and schema declarations. Filesystem plugins are local code;
load them only when you trust the source. Manifest metadata is intentionally
TOML so Bywaf can inspect commandlets, capabilities, topics, and schemas before
plugin Python is imported.

Useful next docs:

- [Terminology](TERMINOLOGY.md)
- [Runtime Model](RUNTIME_MODEL.md)
- [Event Model](EVENT_MODEL.md)
- [Reporting](REPORTING.md)
- [Capability Model](CAPABILITY_MODEL.md)
- [Security Audit](SECURITY_AUDIT.md)
