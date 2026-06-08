# Bywaf FAQ

This FAQ is example-first. Each answer starts with the command you are most
likely to type, then adds a short note about what it does.

## Contents

- [How do I start Bywaf?](#how-do-i-start-bywaf)
- [How do I see what commands are available?](#how-do-i-see-what-commands-are-available)
- [How do I get help for one commandlet?](#how-do-i-get-help-for-one-commandlet)
- [How do I run a normal discovery pipeline?](#how-do-i-run-a-normal-discovery-pipeline)
- [I started a port scanner. How do I see what it found?](#i-started-a-port-scanner-how-do-i-see-what-it-found)
- [Can hostscanner scan DNS names?](#can-hostscanner-scan-dns-names)
- [How do I see Nikto's raw output?](#how-do-i-see-niktos-raw-output)
- [How do I run a pipeline in the background?](#how-do-i-run-a-pipeline-in-the-background)
- [How do I show historical job, step, or pipeline?](#how-do-i-show-historical-job-step-or-pipeline)
- [How do I create a clean project for a client?](#how-do-i-create-a-clean-project-for-a-client)
- [How do I open an existing project?](#how-do-i-open-an-existing-project)
- [How do I switch projects if active job are running?](#how-do-i-switch-projects-if-active-job-are-running)
- [How do I archive a project?](#how-do-i-archive-a-project)
- [How do I create or open an encrypted database?](#how-do-i-create-or-open-an-encrypted-database)
- [How do I save a copy of the current database?](#how-do-i-save-a-copy-of-the-current-database)
- [How do I load another database?](#how-do-i-load-another-database)
- [How do I set a commandlet variable?](#how-do-i-set-a-commandlet-variable)
- [How do I set variables without typing the commandlet prefix each time?](#how-do-i-set-variables-without-typing-the-commandlet-prefix-each-time)
- [How do I set a secret such as a password?](#how-do-i-set-a-secret-such-as-a-password)
- [How do I stop or pause work?](#how-do-i-stop-or-pause-work)
- [When should I use `signal`?](#when-should-i-use-signal)
- [How do I add a note to a step, job, or pipeline?](#how-do-i-add-a-note-to-a-step-job-or-pipeline)
- [How do I import or attach a file as an artifact?](#how-do-i-import-or-attach-a-file-as-an-artifact)
- [How do I find which commandlet produced an artifact?](#how-do-i-find-which-commandlet-produced-an-artifact)
- [How do I see the producing commandlet's parameters and environment?](#how-do-i-see-the-producing-commandlets-parameters-and-environment)
- [How do I verify that an artifact really came from that commandlet step?](#how-do-i-verify-that-an-artifact-really-came-from-that-commandlet-step)
- [How do I export one artifact?](#how-do-i-export-one-artifact)
- [How do I export all artifacts from a step or pipeline?](#how-do-i-export-all-artifacts-from-a-step-or-pipeline)
- [Should I export a bare artifact or an evidence bundle?](#should-i-export-a-bare-artifact-or-an-evidence-bundle)
- [How do I secure exported evidence?](#how-do-i-secure-exported-evidence)
- [How do I search artifacts?](#how-do-i-search-artifacts)
- [How do I find artifacts produced by one commandlet step?](#how-do-i-find-artifacts-produced-by-one-commandlet-step)
- [How do I find which events are associated with a pipeline?](#how-do-i-find-which-events-are-associated-with-a-pipeline)
- [How do I find the results of a commandlet step?](#how-do-i-find-the-results-of-a-commandlet-step)
- [How do I export a findings table?](#how-do-i-export-a-findings-table)
- [How do I run commands from a script?](#how-do-i-run-commands-from-a-script)
- [How do I use targets from a file?](#how-do-i-use-targets-from-a-file)
- [How do I exclude targets from a scan?](#how-do-i-exclude-targets-from-a-scan)
- [How do I inspect events?](#how-do-i-inspect-events)
- [How do I force IPv4 or IPv6 when a command resolves a DNS name?](#how-do-i-force-ipv4-or-ipv6-when-a-command-resolves-a-dns-name)
- [How do I export audit data?](#how-do-i-export-audit-data)
- [How do I load a local plugin?](#how-do-i-load-a-local-plugin)
- [How do I check a plugin manifest?](#how-do-i-check-a-plugin-manifest)

## How do I start Bywaf?

```bash
bywaf
```

During development from the repository root:

```bash
python3 -m bywaf
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

Each step emits structured events into the database. Later step consume those
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

If the scan is still running, use runtime listings to find the active job or pipeline step:

```text
bywaf> job
bywaf> step
```

Then narrow the event view:

```text
bywaf> event step=7
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
bywaf> artifact cat 1
bywaf> artifact show 1
```

Find the artifact attached by the `nikto` pipeline step, preview the body,
inspect its provenance, then save it:

```text
bywaf> artifact export artifact=1 file=nikto.json
```

If you know the step ID, list or save artifacts with the `step=` selector:

```text
bywaf> artifact list step=7
bywaf> artifact export step=7 dir=artifacts/nikto-step-7/
```

If Nikto exits successfully but produces malformed JSON, `results` shows a
`Tool problems` section with the raw-output artifact reference so the parser
failure does not hide the evidence.

For normalized Nikto findings, use the event or report flow:

```text
bywaf> event nikto.finding
bywaf> nikto https://example.com/ | finding_dedupe | finding_report
bywaf> report
bywaf> report pipeline=1
bywaf> report create name=client-a pipeline=1,2,3
bywaf> report show name=client-a
```

Use `event` when you want raw event payloads. Use `report` when you want the
operator-facing grouped finding inbox for recent, pipeline-scoped, job-scoped,
or step-scoped work.

## How do I run a pipeline in the background?

```text
bywaf> hostscanner 192.168.1.0/24& | portscanner&
```

Use `job`, `step`, and `pipeline` to inspect active runtime state:

```text
bywaf> job
bywaf> step
bywaf> pipeline
```

## How do I show historical job, step, or pipeline?

```text
bywaf> job --all
bywaf> step --all
bywaf> pipeline --all
```

Default runtime listings show active work only. Add `--all` to include completed,
failed, stale, or killed entries.

To inspect old failed rows without deleting audit history, combine `--all` with
job-table selectors:

```text
bywaf> job --all status=failed
bywaf> job --all commandlet=missing
bywaf> job --all status=failed commandlet=missing
```

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

## How do I switch projects if active job are running?

```text
bywaf> project use name=client-b --force
```

Without `--force`, Bywaf refuses to switch while active job exist. With
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

In ad hoc mode, `db load` and `db new` update the local active-database pointer
used by later plain `bywaf` startups. Passing `--database path/to/db.sqlite3`
at startup overrides that pointer for the current invocation. Project mode uses
the selected project database instead.

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

An explicit commandlet name always wins over the active `use` context. This is
intentional: scripts can call fully-qualified commandlets such as
`network/portscanner ...` without depending on whatever context the interactive
operator happened to select earlier.

Run the active commandlet with its stored/default variables:

```text
bywaf> run
```

`step` still lists past commandlet executions, and `step <id>` still inspects one
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
bywaf> pause step=7
bywaf> resume step=7
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
bywaf> signal step=7 pause --soft
bywaf> signal job=3 end --hard
bywaf> signal step=7 prune targets=192.168.1.0/24
bywaf> signal step=7 verbosity level=quiet
```

The audit trail records the selector, action, strength, arguments, and receiver
response.

## How do I add a note to a step, job, or pipeline?

```text
bywaf> note add step=7 text=checked manually in browser
bywaf> note add pipeline=2 text=client approved extended scan window
```

Notes are timestamped and attached to the selected runtime entity.

## How do I import or attach a file as an artifact?

```text
bywaf> artifact import file=snapshot.html name=homepage snapshot
bywaf> artifact attach step=7 file=snapshot.html name=homepage snapshot
bywaf> artifact attach artifact=1 step=7
bywaf> artifact attach serial=<durable-serial> file=headers.txt name=headers
```

`artifact import` stores a file in the artifact database without linking it to a
specific step, pipeline, or job. `artifact attach artifact=... step=...` links an
existing artifact to provenance. `artifact attach step=... file=...` is the
shortcut that imports and attaches in one command. Artifacts are linked back to
the main audit database through metadata and hashes.

## How do I find which commandlet produced an artifact?

```text
bywaf> artifact list artifact=1
bywaf> artifact show 1
bywaf> artifact list serial=<artifact-serial>
```

Artifact rows show the producing `commandlet=`, attached `step=` step selector,
`pipeline=`, `job=`, `artifact_id=`, and `sha256=`. `artifact show` expands one
row into a readable detail block with provenance events and the exact export,
verify, list, step, pipeline, and job commands that apply.

## How do I see the producing commandlet's parameters and environment?

```text
bywaf> artifact list artifact=1
bywaf> event step=<step-id-from-artifact-list>
```

`event step=...` shows the step's audit events. Look for:

- `command.run.arguments` for the commandlet arguments after framework
  expansion and redaction.
- `Variables:` for the effective variable snapshot captured for that step.
- `framework.process.run.requested` or `framework.process.stream.requested`
  for process-wrapper argv/cwd/timeout/environment details.

Secret values are redacted, but Bywaf keeps audit-safe identity metadata. For a
secret variable or process environment value, the audit trail shows the secret
name and fingerprint, for example `name=network/ssh_probe.password` and
`fingerprint=hmac-sha256:...`, not the plaintext.

## How do I verify that an artifact really came from that commandlet step?

```text
bywaf> artifact verify artifact=1
bywaf> artifact verify serial=<artifact-serial>
bywaf> event step=<step-id-from-artifact-list>
bywaf> event serial=<artifact-serial>
```

`artifact verify` checks the artifact body hash and cross-checks the artifact
metadata against the main database's `artifact.attached` audit event. Then use
`event step=...` to inspect the producing step's events, source commandlet,
redacted parameters, captured variables, process environment metadata, and
surrounding lifecycle records.

## How do I export one artifact?

```text
bywaf> artifact export artifact=1 file=snapshot.html
bywaf> artifact export serial=<artifact-serial> file=snapshot.html
```

Use `file=` when exactly one artifact matches. If your selector matches multiple
artifacts, Bywaf asks you to use `dir=` instead.

## How do I export all artifacts from a step or pipeline?

```text
bywaf> artifact export step=7 dir=artifacts/step-7/
bywaf> artifact export pipeline=2 dir=artifacts/pipeline-2/
bywaf> artifact export serial=<step-or-pipeline-serial> dir=artifacts/export/
```

For completed work, prefer durable serials because local numeric IDs are only
stable inside the current database. In commands with enough context, such as
`job <id-or-serial>`, you can pass the serial directly.

## Should I export a bare artifact or an evidence bundle?

Use a bare artifact when you only need the file itself:

```text
bywaf> artifact export artifact=1 file=screenshot.png
```

Use an audit/evidence export when you need provenance: the commandlet step, audit
events, variables, notes, hashes, artifact metadata, and related pipeline
context. The fully signed evidence-bundle workflow is still tracked separately,
but today you can export the audit trail alongside artifacts:

```text
bywaf> artifact export step=7 dir=evidence/step-7-artifacts/
bywaf> audit export since=step:7 file=evidence/run-7-audit.jsonl
bywaf> audit export since=step:7 file=evidence/run-7-audit.pdf
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

## How do I find artifacts produced by one commandlet step?

```text
bywaf> artifact list step=7
bywaf> artifact search step=7 name=screenshot
```

Use the step ID shown by `step`; the selector is still `step=...`. For long-term references, use the durable step serial with `serial=...`.

## How do I find which events are associated with a pipeline?

```text
bywaf> pipeline
bywaf> event pipeline=2
bywaf> event serial=<pipeline-serial>
```

`event pipeline=...` shows events scoped to that pipeline. `pipeline --all`
includes historical pipelines.

## How do I find the results of a commandlet step?

```text
bywaf> step
bywaf> event step=7
bywaf> artifact list step=7
```

`event step=...` shows the step's events and captured variables. If the step saved
files, `artifact list step=...` shows the linked artifacts. For finding-producing
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
bywaf> event port.open host=192.168.50.163
bywaf> event port.open host=192.168.50.1,192.168.50.163 sort=host
bywaf> job host=192.168.50.163
bywaf> pipeline host=192.168.50.163
bywaf> step host=192.168.50.163
bywaf> pipeline sort=events
bywaf> pipeline sort=-events
bywaf> event step=7
bywaf> event serial=<durable-serial>
```

`events` defaults to the last 25 events. `event <topic> field=value` filters
topic rows by payload fields. Use `host=` for host-scoped facts such as
`port.open`; it also matches common nested target fields such as `target.host`.
`sort=host`, `sort=protocol`, `sort=state`, `sort=topic`, and `sort=source`
change the row order.
Runtime list commands use the same payload-style filters and show jobs,
pipelines, or steps that have at least one associated matching event. Runtime
tables also accept command-specific `sort=` selectors such as
`pipeline sort=events`; add a leading `-` for descending order, for example
`pipeline sort=-events`. `since=<id>` shows rows after a known local runtime
ID, and `--new` uses an operator-local filesystem cursor to show rows created
since the last check. `--sort=...` is not accepted.

## How do I force IPv4 or IPv6 when a command resolves a DNS name?

For commandlets that expose a native argument string to an external network
tool, use that tool's family flag. For `portscanner`, `arguments="-4 ..."` keeps
only IPv4 addresses from pre-scan DNS resolution, while `arguments="-6 ..."`
keeps only IPv6 addresses. This filtering is implemented through shared
addressing helpers so future DNS-resolving plugins can use the same behavior
instead of carrying their own resolver rules.

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

If a plugin exposes multiple commandlets, use `use=<commandlet>` or select one
after loading with `use <commandlet>`.

## How do I check a plugin manifest?

```bash
bywaf-plugin-manifest path/to/plugin
```

The helper compares Python commandlet metadata with `bywaf.plugin.toml` so
plugin authors can catch missing commandlet, capability, trait, or secret-option
metadata.
