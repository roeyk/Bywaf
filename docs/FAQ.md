# Bywaf FAQ

This FAQ is example-first. Each answer starts with the command you are most
likely to type, then adds a short note about what it does.

## How do I start Bywaf?

```bash
bywaf repl
```

During development from the repository root:

```bash
python3 -m bywaf repl
```

## How do I see what commands are available?

```text
bywaf> help
bywaf> cmds
bywaf> plugins
```

`help` shows built-ins and common command forms. `cmds` lists loaded
commandlets grouped by provider. `plugins` lists loaded plugin providers.

## How do I get help for one commandlet?

```text
bywaf> help hostscanner
bywaf> hostscanner --help
```

`help <commandlet>` is intended to match `<commandlet> --help`.

## How do I run a normal discovery pipeline?

```text
bywaf> hostscanner 192.168.1.0/24 | portscanner | http_probe
```

Each stage emits structured events into the database. Later stages consume those
events instead of scraping terminal output.

## I started a port scanner. How do I see what it found?

```text
bywaf> event port.open
```

That shows the durable `port.open` evidence events. If you want the recent event
tail first, use:

```text
bywaf> events
```

If the scan is still running, use runtime listings to find the active job or run:

```text
bywaf> jobs
bywaf> steps
```

Then narrow the event view:

```text
bywaf> event run=7
```

`portscanner` does not emit one event for every closed port by default. It emits
`port.open` evidence and scan progress/summary events, keeping the database
useful for later correlation.

## Can hostscanner scan DNS names?

Yes. `hostscanner example.com` resolves the name before invoking nmap, records a
`name.resolved` provenance event with the resolved addresses, and emits
`host.found` for any live hosts nmap reports.

## How do I see Nikto's raw output?

```text
bywaf> artifact list
```

Find the artifact attached by the `nikto` run, then save it:

```text
bywaf> artifact export artifact=1 file=nikto.json
```

If you know the run, list or save artifacts for that run:

```text
bywaf> artifact list run=7
bywaf> artifact export run=7 dir=artifacts/nikto-run-7/
```

For normalized Nikto findings, use the event or report flow:

```text
bywaf> event nikto.finding
bywaf> nikto https://example.com/ | finding_dedupe | finding_report
bywaf> report
bywaf> report pipeline=1
```

Use `event` when you want raw event payloads. Use `report` when you want the
operator-facing grouped finding inbox for recent, pipeline-scoped, job-scoped,
or run-scoped work.

## How do I run a pipeline in the background?

```text
bywaf> hostscanner 192.168.1.0/24& | portscanner&
```

Use `jobs`, `steps`, and `pipelines` to inspect active runtime state:

```text
bywaf> jobs
bywaf> steps
bywaf> pipelines
```

## How do I show historical jobs, steps, or pipelines?

```text
bywaf> jobs --all
bywaf> steps --all
bywaf> pipeline list --all
```

Default runtime listings show active work only. Add `--all` to include completed,
failed, stale, or killed entries.

## How do I create a clean project for a client?

```bash
bywaf --new project=client-a
```

This creates:

```text
~/.bywaf/projects/client-a/bywaf.sqlite3
~/.bywaf/projects/client-a/config.toml
~/.bywaf/projects/client-a/history.bywaf
```

## How do I open an existing project?

```bash
bywaf project=client-a
```

From inside the REPL:

```text
bywaf> project list
bywaf> project use name=client-a
```

## How do I switch projects if active jobs are running?

```text
bywaf> project use name=client-b --force
```

Without `--force`, Bywaf refuses to switch while active jobs exist. With
`--force`, Bywaf hard-stops active job processes, marks them killed, audits the
forced stop in the old project database, and then switches to the new project.

## How do I archive a project?

```text
bywaf> project archive file=client-a-project.zip
bywaf> project archive file=client-a-project.bywaf-archive --encrypt
```

`project archive` snapshots framework-owned project state: the event database,
paired artifact database, project config, project history, and SQLite sidecars
if present. It does not include arbitrary files from the working directory.
Use it to preserve or hand off the complete Bywaf project state; use `bundle`
or `audit export` for curated evidence deliverables.

## How do I create or open an encrypted database?

```bash
bywaf --encrypt
bywaf --database client.sqlite3 --encrypt
bywaf --new --encrypt project=client-a
```

Encrypted databases require SQLCipher support. Bywaf prompts for the passphrase
instead of storing it in config or history.

## How do I save a copy of the current database?

```text
bywaf> db export file=snapshot.sqlite3
bywaf> db export --encrypt file=snapshot.sqlite3
```

`db export file=...` makes a copy/export. It does not change the active database.

## How do I load another database?

```text
bywaf> db load file=snapshot.sqlite3
```

If the database is encrypted, Bywaf prompts for the passphrase.

## How do I set a commandlet variable?

```text
bywaf> set http/http_probe.timeout=3
bywaf> set http/http_probe.cookie-file=/tmp/cookies.sqlite
```

Use `set <name>` to show one value:

```text
bywaf> set http/http_probe.timeout
```

## How do I set variables without typing the commandlet prefix each time?

```text
bywaf> use http_probe
bywaf> set timeout=3
bywaf> set cookie-file=/tmp/cookies.sqlite
```

`use <commandlet>` changes interactive variable/completion context. It does not
hide execution state.

Call a commandlet directly by its registered name, such as `http_probe ...`.
Provider-qualified aliases also work when you want the catalog path, such as
`http/http_probe ...`. Slash-delimited names are used for commandlet-scoped
variables, so `set http/http_probe.timeout=3` sets the `timeout` variable for
the `http_probe` commandlet.

Run the active commandlet with its stored/default variables:

```text
bywaf> run
```

`steps` still lists past commandlet executions, and `step <id>` still inspects one
past execution.

## How do I set a secret such as a password?

```text
bywaf> set --secret ssh_check.password=<secret-value>
```

`--secret` stores the value as an opaque reference in the session VarStore and
persists the plaintext only in the active DB's secret table. Bywaf does not
guess based on variable names; use `--secret` when the value is sensitive. If
the DB is plaintext, Bywaf warns that the secret will be stored without
at-rest database encryption.

## How do I stop or pause work?

```text
bywaf> pause run=7
bywaf> resume run=7
bywaf> end job=3
bywaf> end --hard job=3
```

Soft control asks the commandlet to cooperate. Hard control uses process-level
control when needed.

## When should I use `signal`?

Most users should not need `signal` for routine work. Use friendly commands such
as `pause`, `resume`, `end`, and `prune`.

Use `signal` when you want the explicit/auditable lower-level control form:

```text
bywaf> signal run=7 pause --soft
bywaf> signal job=3 end --hard
bywaf> signal run=7 prune targets=192.168.1.0/24
bywaf> signal run=7 verbosity level=quiet
```

The audit trail records the selector, action, strength, arguments, and receiver
response.

## How do I add a note to a run, job, or pipeline?

```text
bywaf> note add run=7 text=checked manually in browser
bywaf> note add pipeline=2 text=client approved extended scan window
```

Notes are timestamped and attached to the selected runtime entity.

## How do I import or attach a file as an artifact?

```text
bywaf> artifact import file=snapshot.html name=homepage snapshot
bywaf> artifact attach run=7 file=snapshot.html name=homepage snapshot
bywaf> artifact attach artifact=1 run=7
bywaf> artifact attach serial=<durable-serial> file=headers.txt name=headers
```

`artifact import` stores a file in the artifact database without linking it to a
specific run, pipeline, or job. `artifact attach artifact=... run=...` links an
existing artifact to provenance. `artifact attach run=... file=...` is the
shortcut that imports and attaches in one command. Artifacts are linked back to
the main audit database through metadata and hashes.

## How do I find which commandlet produced an artifact?

```text
bywaf> artifact list artifact=1
bywaf> artifact list serial=<artifact-serial>
```

Artifact rows show the producing `commandlet=`, attached `run=`,
`pipeline=`, `job=`, `artifact_id=`, and `sha256=`.

## How do I see the producing commandlet's parameters and environment?

```text
bywaf> artifact list artifact=1
bywaf> event run=<run-id-from-artifact-list>
```

`event run=...` shows the run's audit events. Look for:

- `command.run.arguments` for the commandlet arguments after framework
  expansion and redaction.
- `Variables:` for the effective variable snapshot captured for that run.
- `framework.process.run.requested` or `framework.process.stream.requested`
  for process-wrapper argv/cwd/timeout/environment details.

Secret values are redacted, but Bywaf keeps audit-safe identity metadata. For a
secret variable or process environment value, the audit trail shows the secret
name and fingerprint, for example `name=network/ssh_probe.password` and
`fingerprint=hmac-sha256:...`, not the plaintext.

## How do I verify that an artifact really came from that commandlet run?

```text
bywaf> artifact verify artifact=1
bywaf> artifact verify serial=<artifact-serial>
bywaf> event run=<run-id-from-artifact-list>
bywaf> event serial=<artifact-serial>
```

`artifact verify` checks the artifact body hash and cross-checks the artifact
metadata against the main database's `artifact.attached` audit event. Then use
`event run=...` to inspect the producing run's events, source commandlet,
redacted parameters, captured variables, process environment metadata, and
surrounding lifecycle records.

## How do I export one artifact?

```text
bywaf> artifact export artifact=1 file=snapshot.html
bywaf> artifact export serial=<artifact-serial> file=snapshot.html
```

Use `file=` when exactly one artifact matches. If your selector matches multiple
artifacts, Bywaf asks you to use `dir=` instead.

## How do I export all artifacts from a run or pipeline?

```text
bywaf> artifact export run=7 dir=artifacts/run-7/
bywaf> artifact export pipeline=2 dir=artifacts/pipeline-2/
bywaf> artifact export serial=<run-or-pipeline-serial> dir=artifacts/export/
```

For completed work, prefer durable `serial=` selectors because local numeric IDs
are only stable inside the current database.

## Should I export a bare artifact or an evidence bundle?

Use a bare artifact when you only need the file itself:

```text
bywaf> artifact export artifact=1 file=screenshot.png
```

Use an audit/evidence export when you need provenance: the commandlet run, audit
events, variables, notes, hashes, artifact metadata, and related pipeline
context. The fully signed evidence-bundle workflow is still tracked separately,
but today you can export the audit trail alongside artifacts:

```text
bywaf> artifact export run=7 dir=evidence/run-7-artifacts/
bywaf> audit export since=run=7 file=evidence/run-7-audit.jsonl
bywaf> audit export since=run=7 file=evidence/run-7-audit.pdf
```

## How do I secure exported evidence?

```text
bywaf> audit export --encrypt file=evidence.sqlite3
bywaf> audit export --encrypt file=evidence.pdf
```

Encrypted SQLite audit exports use SQLCipher. Encrypted PDF export uses the
configured PDF encryption support. Bare artifact files are normal filesystem
files after export, so store them in an encrypted directory/archive or keep them
inside an encrypted Bywaf artifact database when at-rest protection matters.

## How do I search artifacts?

```text
bywaf> artifact search name=homepage
bywaf> artifact search filename=snapshot --regexp
bywaf> artifact search content=Server
```

Use `name=`, `filename=`, `note=`, and `content=` to narrow searches.

## How do I find artifacts produced by one commandlet run?

```text
bywaf> artifact list run=7
bywaf> artifact search run=7 name=screenshot
```

Use the step ID shown by `steps`, or use the durable run serial with `serial=...`.

## How do I find which events are associated with a pipeline?

```text
bywaf> pipeline list
bywaf> event pipeline=2
bywaf> event serial=<pipeline-serial>
```

`event pipeline=...` shows events scoped to that pipeline. `pipeline list --all`
includes historical pipelines.

## How do I find the results of a commandlet step?

```text
bywaf> steps
bywaf> event run=7
bywaf> artifact list run=7
```

`event run=...` shows the run's events and captured variables. If the run saved
files, `artifact list run=...` shows the linked artifacts. For finding-producing
tools, you can also render a findings table:

```text
bywaf> finding_report source=tools
bywaf> finding_report source=dedupe
```

## How do I export a findings table?

```text
bywaf> finding_report source=dedupe export=report.md
bywaf> finding_report source=dedupe export=report.csv
```

The reporter uses normalized finding events and the table-rendering provider.

## How do I run commands from a script?

```text
bywaf> script load file=scan.bywaf
```

Scripts contain one command or pipeline per line. Lines beginning with `#` are
comments.

## How do I use targets from a file?

```text
bywaf> hostscanner @targets.txt
bywaf> hostscanner @lines:targets.txt
```

`@file` expands file content as an argument. `@lines:file` expands each
non-empty line as a separate argument.

## How do I exclude targets from a scan?

```text
bywaf> hostscanner 192.168.1.0/24 except=192.168.1.10
bywaf> hostscanner 192.168.1.0/24 except=@excluded.txt
```

Exception lists are included in test/plan output and audit records.

## How do I inspect events?

```text
bywaf> events
bywaf> events tail last=50
bywaf> event host.found
bywaf> event run=7
bywaf> event serial=<durable-serial>
```

`events` defaults to the last 25 events.

## How do I export audit data?

```text
bywaf> audit show
bywaf> audit export file=audit.jsonl
bywaf> audit export since=20260519 file=audit.md
```

Date/time selectors default to time unless another selector type is specified.

## How do I load a local plugin?

```text
bywaf> plugin load=./my_plugin
bywaf> plugin load=~/bywaf-plugins/my_plugin
bywaf> pload ./my_plugin --force
```

Bundled plugins are loaded from the configured plugin list. Filesystem plugins
can be loaded explicitly by path.

Use `--use` to switch to the loaded commandlet when the plugin exposes one
commandlet:

```text
bywaf> pload ./my_plugin --force --use
```

If a plugin exposes multiple commandlets, use `--use=<commandlet>` or select one
after loading with `use <commandlet>`.

## How do I check a plugin manifest?

```bash
bywaf-plugin-manifest path/to/plugin
```

The helper compares Python commandlet metadata with `bywaf.plugin.toml` so
plugin authors can catch missing commandlet, capability, trait, or secret-option
metadata.
