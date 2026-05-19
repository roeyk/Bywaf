# Bywaf

Bywaf is a highly-auditable Python 3 commandlet framework for authorized web
application and network testing workflows.

Typical assessments often look like:

- run a tool;
- copy output;
- transform output;
- save notes somewhere;
- run another tool;
- lose provenance;
- forget assumptions;
- lose intermediate state.

Bywaf replaces those manual handoffs with structured events, durable runtime
records, artifacts, notes, policy decisions, and replayable workflow state. It
presents a Metasploit-like interactive shell, loads commandlets from plugins,
and connects commandlets through a SQLite-backed event bus.

The core workflow is intentionally simple:

```text
hostscanner 192.168.1.0/24 | portscanner | http_probe | webfin | nikto
```

That command expresses a complete chain:

```text
hostscanner  -> emits host.found
portscanner  -> consumes host.found, emits port.open
http_probe   -> consumes port.open, emits http.endpoint
webfin       -> consumes http.endpoint, emits web.fingerprint
nikto        -> consumes http.endpoint/web.fingerprint, emits vulnerability events
```

The important difference from a plain stdout pipe is that each stage publishes
normalized events into a durable database. Later commandlets, reports,
artifact searches, audit exports, and future GUI/web frontends can inspect the
same recorded facts instead of scraping terminal scrollback.

## Why Not Bash, Metasploit, Airflow, Or Scripts?

| Tool | Good at | Bywaf's distinction |
| --- | --- | --- |
| Bash | Fast shell glue | Durable event flow, runtime records, notes, artifacts, and provenance are built in. |
| Metasploit | Exploitation workflows and module ecosystem | Bywaf focuses on auditable event-driven orchestration over normalized assessment data. |
| Airflow | Scheduled batch/data pipelines | Bywaf is interactive, operator-driven, and built around live security assessment workflows. |
| Python scripts | Maximum flexibility | Bywaf gives scripts a common shell, plugin API, event store, audit trail, and reusable workflow state. |

Use Bywaf only on systems and networks where you have explicit authorization.

## Project References

Project changes are summarized in [CHANGELOG.md](CHANGELOG.md).
Common task examples are collected in [FAQ.md](FAQ.md).
Evolving framework design notes are tracked in [DESIGN.md](DESIGN.md).
Core architectural references:

- [TERMINOLOGY.md](TERMINOLOGY.md) defines jobs, pipelines, runs, events,
  topics, commandlets, plugins, capabilities, local IDs, and serials.
- [RUNTIME_MODEL.md](RUNTIME_MODEL.md) explains runtime entities, lifecycle,
  foreground/background execution, control signals, and variable snapshots.
- [EVENT_MODEL.md](EVENT_MODEL.md) explains event rows, topics, replay,
  framework requests, artifacts, notes, and provenance.
- [PERSISTENCE_MODEL.md](PERSISTENCE_MODEL.md) explains the event, runtime,
  artifact, maintenance, and variable store contracts.
- [CAPABILITY_MODEL.md](CAPABILITY_MODEL.md) explains capability auditing,
  policy direction, and plugin integration types.
- [SYSTEM_BLOCK_DIAGRAM.pdf](SYSTEM_BLOCK_DIAGRAM.pdf) shows live runtime flow
  and durable data flow through the system.
- [SYSTEM_DATAFLOW_DIAGRAM.pdf](SYSTEM_DATAFLOW_DIAGRAM.pdf) focuses on command
  input, event, artifact, audit, request, and report data movement.

# Installation

During development, run Bywaf from the repository root:

```bash
cd bywaf
python3 -m bywaf --help
python3 -m bywaf repl
```

For an editable local install:

```bash
python3 -m pip install -e .
bywaf --help
bywaf repl
```

For a local pip package build:

```bash
scripts/build_pip_package.sh
python3 -m pip install dist/bywaf-0.9.2-py3-none-any.whl
bywaf --help
```

For a local Debian package build, install the Debian build dependencies and
write artifacts under `dist/deb/`:

```bash
sudo apt install debhelper dh-python pybuild-plugin-pyproject python3-all python3-setuptools python3-prompt-toolkit
scripts/build_deb_package.sh
sudo apt install dist/deb/bywaf_0.9.2-1_all.deb
bywaf --help
```

For a local RPM package build, install RPM build tooling and write release
artifacts under `dist/rpm/`:

```bash
sudo apt install rpm python3-build python3-installer
scripts/build_rpm_package.sh
```

Packaging smoke scripts:

```bash
scripts/build_release_packages.sh
tests/scripts/smoke_pip_package.sh
tests/scripts/smoke_rpm_package.sh
tests/scripts/smoke_plugin_install_paths.sh
tests/scripts/smoke_installed_package.sh
```

Release tags named `v*` trigger the GitHub Actions release workflow. The
workflow builds pip, Debian, and RPM artifacts with the same local scripts,
smoke-tests the package outputs, uploads the artifacts to the workflow run, and
attaches them to the GitHub Release for the tag.

The project metadata defines a console script named `bywaf`, so packaged
installations can expose Bywaf as a normal command instead of requiring
`python3 -m bywaf`.

Bywaf can also be embedded as a Python library. A local GUI or web service
should use the public session facade instead of scraping REPL output:

```python
from pathlib import Path
from bywaf import BywafSession

session = BywafSession.open(Path(".bywaf/bywaf.sqlite3"))
session.run("hostscanner 127.0.0.1")
hosts = session.events(topic="host.found")
jobs = session.jobs()
```

The host and port scanner commandlets use `nmap` through a Python adapter. A
local `nmap` binary is required for real scans. The adapter prefers `nmaplib`,
then `python-nmap`, then `nmapthon`, then `libnmap`.

## Dependency Summary

```text
nmap                       required for hostscanner and portscanner
nikto                      required for the nikto wrapper commandlet
eyewitness                 required for the eyewitness screenshot wrapper
kismet                     required for the wifi_scan wireless wrapper
prompt_toolkit             required for rich interactive REPL completion
libnmap/python-nmap/etc.   Python nmap adapter; Bywaf tries supported adapters
sqlcipher3-binary          optional Python SQLCipher driver for encrypted DBs
sqlcipher                  optional system SQLCipher tooling/library
cryptography               optional for signing-key management and bundle signing
python-docx/openpyxl       optional DOCX/XLSX table rendering backends
dnspython                  optional for dns_lookup
impacket                   optional for smb_probe
ldap3                      optional for ldap_probe
paramiko                   optional for ssh_probe
pysnmp                     optional for snmp_get
shodan                     optional for shodan_lookup
yara-python                optional for yara_scan
```

Install all dependencies with one of these command sets from the repository
root.

Debian / Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv python3-setuptools \
  python3-build python3-installer python3-prompt-toolkit nmap \
  sqlcipher libsqlcipher-dev debhelper dh-python pybuild-plugin-pyproject \
  python3-all rpm nikto kismet
python3 -m pip install -e '.[plugins,reporting,signing,sqlcipher]'
python3 -m pip install libnmap python-nmap nmapthon
```

Fedora / RHEL-family:

```bash
sudo dnf install -y python3 python3-pip python3-setuptools python3-build \
  python3-installer python3-prompt-toolkit nmap sqlcipher sqlcipher-devel \
  rpm-build nikto kismet
python3 -m pip install -e '.[plugins,reporting,signing,sqlcipher]'
python3 -m pip install libnmap python-nmap nmapthon
```

Use `yum` instead of `dnf` on older RHEL-family systems. Some external-wrapper
tools, especially `eyewitness`, `nikto`, and `kismet`, may require a
security-focused distribution, EPEL, or an upstream installation source.

Bywaf plugins are intended to wrap useful external tools and normalize their
results into the central event database. That removes manual handoffs such as
copying hosts to notes or intermediate files: one plugin can discover hosts,
another can consume those host events, and later plugins can continue the
workflow from the same stored data.

Execution-time plugin variables are scoped by commandlet. A plugin uses
`context.vars.get("name")` for its own variables and cannot enumerate another
plugin's variables through that API. Explicit global variables use
`context.vars.get_global("name")`. When a commandlet run starts, Bywaf snapshots
the effective commandlet and global variables into SQLite under that
`command_run_id`; `event run=<id>` displays the captured variables so runs remain
auditable and reproducible even when session variables change later.
Runtime entities have two identities: local IDs for interactive typing
(`job=12`, `run=1`, `pipeline=2`) and durable serials for audit/provenance.
Local IDs are stable inside the current database and are never reused there,
but they are not portable across replay/import into another database. Use
`event serial=<serial>` when you want to inspect by the durable identifier.
Explicit `load plugin=...` and `load script=...` operations also receive
resource serials, so the load itself and the script commands it executed can be
reviewed later.

Plugins that need interpreter-owned actions use request events instead of
direct method calls. For example, a plugin can publish
`shell.prompt.requested`; the foreground REPL validates the request and records
either `shell.prompt.updated` or `framework.request.denied` for auditability.
Plugins also declare intended capabilities on `CommandSpec`; Bywaf records
audit-only `plugin.capability.used` and `plugin.capability.missing` events so
operators can compare intended behavior with actual behavior.
Plugin event-bus access should go through `context.events`, which audits
`db.read:<topic>` and `db.write:<topic>` capability usage. Raw `context.db`
access is retained for privileged/internal framework commandlets during the
transition and audits `db.raw`.

Encrypted databases require SQLCipher support. On Debian or Ubuntu, install the
SQLCipher library and use the optional Python extra:

```bash
sudo apt install sqlcipher libsqlcipher-dev
python3 -m pip install -e '.[sqlcipher]'
```

Install optional table export backends with:

```bash
python3 -m pip install -e '.[reporting]'
```

# Starting Bywaf

Start the interactive shell:

```bash
bywaf
```

or, from a source checkout:

```bash
python3 -m bywaf
```

Create or open the default database with SQLCipher encryption:

```bash
bywaf --encrypt
bywaf --database client.sqlite3 --encrypt
```

Run one command non-interactively:

```bash
bywaf run ls
bywaf run cat README.md
bywaf run 'hostscanner 127.0.0.1 | portscanner'
```

Simple `run` commands do not need quotes. Use quotes when the command contains
shell metacharacters such as `|`, `&`, `>`, or spaces that must be preserved
inside a single argument.

# REPL Basics

The REPL prompt is:

```text
bywaf>
```

Commandlets can be run directly:

```text
bywaf> ls
bywaf> cat README.md
bywaf> hostscanner 127.0.0.1
```

Built-in commands manage the shell and the event database:

```text
help
help <command>
plugins
cmds
vars
history
info
job <list|show|cancel|end|kill>
pipeline <list|show|cancel|end|kill>
signal <job=id|run=id|serial=id> <action> [--soft|--hard] [key=value ...]
cancel <job=id|pipeline=id|run=id>
end [--soft|--hard] <job=id|pipeline=id|run=id>
kill [--soft|--hard] <job=id|pipeline=id|run=id>
jobs
runs
events [tail|--tail] [last=N]
topics
db <status|path|checkpoint|vacuum|new|encrypt|decrypt|rekey>
event <topic|job=id|run=id|pipeline=id|serial=id>
load <resource>
save <resource>
exit
```

`help <command>` shows the same help as `<command> --help` for commandlets.
Ctrl-C in the interactive shell asks whether to quit; answering yes exits
through the normal shutdown path, including the SQLite checkpoint.

# Commandlets

A commandlet is an executable unit exposed by a plugin. Each commandlet declares
its name, description, arguments, consumed topics, and emitted topics.

Examples:

```text
bywaf> help hostscanner
bywaf> hostscanner --help
bywaf> portscanner --help
```

Many scanning commandlets support `-s` or `--silent` to suppress console alerts.
Commandlets request alerts through the framework using the database; the
framework validates the request, stores a structured `console.alert` event, and
prints it unless silent mode is active:

```text
hostscanner <hostscanner-...>: discovered host 127.0.0.1
portscanner <portscanner-...>: discovered port 127.0.0.1:80/tcp
```

Commandlets can also declare tab-completion behavior for their arguments and
options. For example, `ls [path]`, `cat <path>`, and `less <path>` get filename
completion because those commandlets declare path/file completion in their
plugin specs. Other completion specs include `topic`, `run`, `pipeline`, `job`,
and `plugin`, so plugin authors can make hand-typed commands much easier to
complete correctly.
Runtime entity completions include prompt-toolkit metadata when available, such
as serial, status/source, event counts, and the current number of attached
artifacts.

Interactive shells use `prompt_toolkit` when a real terminal is available.
`Ctrl-Space` enters completion-selection mode by opening the menu and selecting
the first candidate. Then arrow keys move through candidates, `Enter` selects
the highlighted completion, and `Esc` returns to the command line. A bottom
toolbar shows that hint while a completion menu is open. The selection-mode key
is configurable with `vars completion.select-key=<key>` using prompt-toolkit key
names, because some desktop environments or terminal stacks reserve
`Ctrl-Space`. `vars completion.wasd-selection=true` enables optional
WASD-style menu navigation (`w`/`a` move backward, `s`/`d` move forward,
following prompt-toolkit's flat completion order), but it is off by default so
ordinary typing is not intercepted. Minimal
non-interactive environments fall back to readline-style completion.

Plugin authors should use `context.output()`, `context.table()`,
`context.alert()`, `context.progress()`, `context.page_file()`, and
`context.process` instead of direct `print()` calls, direct terminal control,
or direct subprocess calls. These helpers keep terminal output, progress, and
external tool execution auditable and make the same commandlets usable from a
future GUI or web frontend.

Progress is separate from findings. A finding is durable evidence such as
`host.found` or `port.open`; progress is operational state such as "42% through
the TCP scan." Commandlets report progress through structured events:

```python
context.progress_started(phase="tcp_scan", total=1000, unit="ports")
context.progress(phase="tcp_scan", current=420, total=1000, unit="ports")
context.progress_completed(phase="tcp_scan", current=1000, total=1000, unit="ports")
```

Bywaf enforces progress throttling in the framework. Configure it with global
session variables:

```text
bywaf> vars global.progress.min-interval-ms=250
bywaf> vars global.progress.min-percent-delta=1
```

Audit logs are stored as SQLite events. Use `audit show ...` to inspect them
and `audit export file=audit.jsonl`, `audit export file=audit.pdf`, or
`audit export file=audit.sqlite3` to hand off a copy.

```text
bywaf> audit show topic=console.alert since=20260517 until=20260518
bywaf> audit export file=audit.pdf since=run=<command-run-id>
bywaf> audit export --encrypt file=audit.sqlite3
bywaf> audit export --encrypt file=audit.pdf
```

Unqualified `since=` and `until=` audit bounds default to `time:`. Encrypted
SQLite audit exports use SQLCipher. Encrypted PDF export uses `pikepdf` when
available, otherwise the external `qpdf` command.

# Signing Keys

Bywaf keeps user signing and verification keys under `~/.bywaf/keys`, outside
project databases. Private keys are encrypted with a passphrase, and signing
operations ask for that passphrase instead of storing it in the project.

```text
bywaf> key list
bywaf> key generate name=firm-evidence
bywaf> key show name=firm-evidence
bywaf> key import public file=reviewer.pub name=reviewer
bywaf> key export public name=firm-evidence file=firm-evidence.pub
bywaf> key test name=firm-evidence
```

`key list` shows computed signing state from the key files themselves:
`available`, `locked`, `verify-only`, or `invalid`. The framework does not trust
a user-edited `can_sign` flag in metadata. Future signed bundle and audit-export
commands will complete `key=` values from this keyring.

# Evidence Bundles

Bundles collect audit records, evidence artifacts, and report artifacts into a
durable manifest. The bundle definition is stored in the event DB as
`bundle.created`, `bundle.item.added`, `bundle.sealed`, and `bundle.exported`
events. Sealing hashes the current bundle contents; `--sign key=...` also signs
that hashable manifest with a key from `~/.bywaf/keys`.

```text
bywaf> bundle create name=client-a
bywaf> bundle add name=client-a audit since=20260501 until=20260519
bywaf> bundle add name=client-a evidence commandlet=nikto,webfin
bywaf> bundle seal name=client-a --sign key=firm-evidence
bywaf> bundle verify name=client-a
bywaf> bundle export name=client-a file=client-a.bundle.json
```

For artifact-backed bundle items, `commandlet=` accepts comma-separated
commandlet names. The first implementation exports JSON bundles with artifact
bodies encoded as Base64 and verifies signatures against the keyring. Sealed
bundles reject additional `bundle add` operations; create a new bundle when more
material needs to be added after sealing.

# Plugins

A plugin provider groups related commandlets. The `plugins` command lists loaded
providers:

```text
bywaf> plugins
discovery
http
network
os
runtime
storage
```

The `cmds` command lists commandlets grouped by provider:

```text
bywaf> cmds
discovery
  hostscanner
http
  eyewitness
  http_headers
  http_probe
  nikto
  webfin
network
  portscanner
os
  cat
  less
  ls
runtime
  job
storage
  db
wireless
  wifi_scan
```

Bundled plugins are listed in `bywaf/plugins/plugins.toml`. Adding a plugin file
is not enough to load it by default; add its dotted path to that config and add
or update its sidecar manifest, such as `bywaf/plugins/http/nikto.plugin.toml`.

Load an additional plugin by name from `.bywaf/plugins`:

```text
bywaf> load plugin=myplugin
```

Load a plugin from an explicit filesystem path:

```text
bywaf> load plugin=./plugins/myplugin
bywaf> load plugin=~/bywaf-plugins/myplugin
```

# Pipelines

Pipelines connect commandlets with `|`. Prefix the expression with `name:` to
name the pipeline without consuming commandlet arguments:

```text
bywaf> hostscanner 127.0.0.1 | portscanner
bywaf> client subnet scan: hostscanner 127.0.0.1 | portscanner
```

The runner executes each stage in order. Events emitted by one stage are passed
to the next stage as input. Events are also stored in SQLite with a pipeline ID
and command run ID.

This model allows downstream commandlets to consume only the output relevant to
the current pipeline, rather than every historical event in the database.

Attach a new background commandlet to an existing pipeline:

```text
bywaf> pipeline attach <pipeline-id> portscanner run=<producer-run-id> since=beginning
bywaf> pipeline attach <pipeline-id> http_probe since=now
```

The attach selectors are orthogonal:

- `<pipeline-id>` chooses the pipeline the new command run joins.
- `run=<producer-run-id>` optionally narrows input to one upstream producer run.
- `since=beginning` replays matching historical events, then listens for new
  events.
- `since=now` ignores historical events and starts from the current event
  high-water mark.

If `run=` is omitted, the attached commandlet reads matching events from the
whole pipeline.

# Runtime Names

Name the current command run with a stage-local `name=` selector:

```text
bywaf> hostscanner 127.0.0.1 name=localhost sweep
```

Name or inspect runtime entities after they exist:

```text
bywaf> name run=<command-run-id> localhost sweep
bywaf> name pipeline=<pipeline-id> client subnet scan
bywaf> name job=<job-id> background listener
bywaf> name run=<command-run-id>
```

The explicit keyed form is `text=`, for example `name run=<id> text=localhost sweep`.

Assigned names appear in `runs`, `pipelines`, and `jobs` listings.

# Framework Notes

Any commandlet stage can include a framework-level `note=` selector. The runner
strips it before the commandlet receives arguments and records an audited
`note.attached` event with the job, pipeline, and command-run IDs.

```text
bywaf> hostscanner 10.0.0.0/24 note=client-approved internal subnet
```

If `note=` is the last selector in a stage, it consumes the rest of that stage
without requiring quotes:

```text
bywaf> hostscanner targets note=scope approved | portscanner note=top ports
```

Review attached notes with the `note` commandlet. Output and file exports use
timestamp-first lines:

```text
bywaf> note run=<command-run-id>
bywaf> note pipeline=<pipeline-id>
bywaf> note job=<job-id> file=notes.txt
bywaf> note add run=<command-run-id> text=follow-up note
```

Notes are append-only. Adding another note creates another timestamped
`note.attached` event instead of replacing earlier notes.

# Artifacts

Artifacts are evidence files attached to a run, pipeline, or job. Artifact
bodies are stored in a separate artifact database next to the main database.
If the main database is encrypted, the artifact database is encrypted with the
same session passphrase. If the main database is plaintext, the artifact
database is plaintext too. The main database stores timestamped provenance
events such as `artifact.attached` and `artifact.exported`; it does not store
artifact bodies. Bywaf derives the artifact DB path from the active main DB path
so the two files remain an integrity pair; arbitrary artifact DB switching is
intentionally not exposed by default.

Start Bywaf with an encrypted database when you want SQLCipher-protected
artifact bodies:

```text
bywaf --encrypt
```

Attach one or more files:

```text
bywaf> artifact attach run=<command-run-id> file=snapshot.html name='Landing page'
bywaf> artifact attach serial=<run-or-pipeline-or-job-serial> file=snapshot.html
bywaf> artifact attach run=<command-run-id> file=snapshot.html file=headers.txt
bywaf> artifact attach pipeline=<pipeline-id> file=report.json note=initial report
```

List, search, save, and verify artifacts:

```text
bywaf> artifact list run=<command-run-id>
bywaf> search run=<command-run-id> name=landing
bywaf> search run=<command-run-id> filename=snapshot.html
bywaf> search run=<command-run-id> content=csrf
bywaf> artifact search run=<command-run-id> --regexp filename='.*\\.png'
bywaf> artifact replace artifact=1 file=snapshot-v2.html
bywaf> artifact remove artifact=1
bywaf> artifact save artifact=1 file=snapshot.html
bywaf> artifact save serial=<artifact-serial> file=snapshot.html
bywaf> artifact save run=<command-run-id> dir=artifacts/
bywaf> artifact verify pipeline=<pipeline-id>
```

Use `name=` for human-readable artifact labels; if omitted, the source filename
is used. The `search` commandlet, and its `artifact search` alias, search
artifact metadata quickly. `name=`, `filename=`, `note=`, and `content=` narrow
the search to artifact names, source filenames, notes, or decoded text contents. Add
`--regexp` to treat those field values as Python regular expressions. Any
commandlet whose main action is text search should follow the same `--regexp`
convention. `since=` and `until=` restrict matches by artifact creation time.
Use `file=` when saving exactly one artifact. Use `dir=` when saving a set. If
`file=` matches multiple artifacts, Bywaf reports that clearly and asks you to
use `dir=` instead.
For `artifact attach`, `serial=` may refer to a run, pipeline, or job serial.
Artifact serials identify existing artifact rows for listing, searching,
saving, and verifying; artifacts are not attached to other artifacts.

# At-File Arguments

Any commandlet argument can use framework-level at-file expansion. Expansion
happens before the commandlet receives its argument list and is audited as a
framework argument expansion. When the active database is encrypted and artifact
storage is available, the expanded input file is also attached as an encrypted
provenance artifact.

```text
bywaf> hostscanner @lines:targets.txt
bywaf> hostscanner 192.168.1.1-255 except=@lines:do-not-scan.txt
bywaf> http_probe @target.txt
bywaf> echo @@literal-at-sign
```

Supported forms:

- `@file`: read the file as one text argument
- `@raw:file`: read the file as one text argument
- `@lines:file`: expand each non-empty line into a separate argument
- `@@value`: pass `@value` literally

Scanner commandlets support `except=` for exclusion lists. Values may be comma
separated or file-backed through `@lines:`.

Tab completion preserves these prefixes while completing filesystem paths.

# Variable Expansion

Bywaf expands `$variables` before commandlets receive their argument list.
Unquoted and double-quoted variables expand; single-quoted variables are passed
literally.

```text
bywaf> use hostscanner
bywaf> vars targets=192.168.1.1 192.168.1.2
bywaf> hostscanner $targets
bywaf> hostscanner "$targets"
bywaf> hostscanner '$targets'
```

Resolution checks the exact variable name first, then the active commandlet
scope, then `global.`. For example, `$targets` in `hostscanner` checks
`targets`, `hostscanner.targets`, and `global.targets`. Variable expansion is
audited as `framework.variable.expanded`.

# Plans And Policy

Commandlets can expose a framework-owned plan hook. Use `--test` to show the
intended action and exit without running, or `--yes` to approve a required plan
non-interactively:

```text
bywaf> hostscanner 192.168.1.0/24 --test
bywaf> hostscanner 192.168.1.0/24 --yes
```

Plans are audited as `plan.requested`, evaluated as `policy.evaluated`, and
approved or denied as `plan.approved` / `plan.denied` with `approved_by=<os
user>`. Suggested repairs, such as pruning out-of-scope targets for one run,
are audited as `plan.repair.applied` or `plan.repair.denied`.

Initial network policy variables:

```text
bywaf> vars global.policy.network.allow=192.168.1.0/24
bywaf> vars global.policy.network.deny=169.254.169.254/32,192.168.1.50
bywaf> vars global.plan.required=true
```

The policy layer applies to the run being launched. Repairs do not mutate source
files, saved variables, or command history.

# Command Continuation And Sequences

Use a trailing backslash to continue a command across physical lines in the
interactive shell or in scripts:

```text
bywaf> hostscanner \
... 192.168.0.0/24
```

Separate multiple commands with semicolons when they should run sequentially:

```text
bywaf> vars target=127.0.0.1; vars; topics
```

Semicolons inside quotes are preserved as part of the argument text.

# Background Execution

Append `&` to background a commandlet or pipeline:

```text
bywaf> hostscanner 192.168.0.1-255 &
```

Normal commandlet execution is job-audited through the database. Foreground
commandlets run in-process but still record `job.requested`, `job.claimed`,
`job.started`, and `job.finished` or `job.failed`. Background jobs use the same
job lifecycle, but a worker process claims and runs the queued job. Foreground
management commands such as `db ...` and `job ...` run directly.

Stage-level backgrounding works inside pipelines:

```text
bywaf> hostscanner 192.168.0.1-255 & | portscanner &
```

In that example, `portscanner` listens for `host.found` rows created by the
immediately upstream `hostscanner` run in the same pipeline. It does not consume
unrelated `host.found` rows from older scans.

A pipeline groups one or more runs in the same command expression or attached
workflow. A run is one commandlet invocation inside that pipeline, such as the
specific `hostscanner` stage or `portscanner` stage. A job is the supervised
foreground/background execution lifecycle that runs one or more of those
commandlet invocations. Operationally, jobs are chained together into pipelines
by the runs they supervise; one job may contribute the whole chain, or multiple
jobs may contribute runs when commandlets are attached later. See
`TERMINOLOGY.md` for the canonical definitions of jobs, pipelines, runs, local
IDs, serials, events, and topics.

Show the currently active runtime entities:

```text
bywaf> info
```

List active jobs, or all jobs with an explicit active marker:

```text
bywaf> job list
bywaf> job list --all
bywaf> job list --page
bywaf> jobs --all
```

Show one job:

```text
bywaf> job show <id>
```

Soft-cancel a job so commandlets that check cancellation can exit cleanly:

```text
bywaf> job cancel <id>
```

End a job. By default this is cooperative, like `cancel`; add `--hard` to
force-stop the process:

```text
bywaf> job end <id>
bywaf> job end --hard <id>
bywaf> job kill --hard <id>
```

Pipelines can be inspected and controlled the same way:

```text
bywaf> pipeline list
bywaf> pipeline list --all
bywaf> pipeline list --page
bywaf> pipeline show <id>
bywaf> pipeline cancel <id>
bywaf> pipeline end <id>
bywaf> pipeline kill --hard <id>
```

`job list`, `runs`, and `pipeline list` show active runtime state by default.
Use `--all` to include historical entries. These commands render table views
with local ID, durable serial, lifecycle state, names, timestamps, and an
`ARTIFACTS` column counting artifacts attached so far. Set
`vars global.listing.active-format=long` to include the state timestamp in the
state column; set it to `short` for compact lifecycle labels. Use `--page` on
list actions such as `job list`, `pipeline list`, and `artifact list` to view
long output through the framework pager.

`watchdog` is Bywaf's default service-style runtime monitor. Interactive
sessions start one session-scoped watchdog automatically and stop it during
orderly shutdown. You can also run it manually to tune thresholds or test the
current DB:

```text
bywaf> watchdog --once
bywaf> watchdog interval=10 timeout=300 stall-threshold=120 error-threshold=10 &
```

The watchdog emits `watchdog.timeout`, `watchdog.stalled`, and
`watchdog.error_rate` events when active jobs exceed the configured limits.

For live runtime control, `signal` is the canonical command for a concrete
receiver: a job, a command run, or a `serial=` that resolves to one of those.
A pipeline is a grouping scope, not executing code, so it does not receive
plugin-domain signals directly. Use pipeline-aware commands such as `pause
pipeline=...` or `end --hard pipeline=...` when you want the framework to fan
out control over jobs associated with a pipeline. Framework-native signals such
as `pause`, `resume`, `stop`, `end`, and `kill` apply the existing framework
controls; plugin-domain signals such as `prune`, `mute`, `unmute`, and
`verbosity` are delivered for commandlets to apply or ignore.

```text
bywaf> signal run=<command-run-id> prune targets=192.168.1.0/24
bywaf> signal run=<command-run-id> mute
bywaf> signal serial=<run-or-job-serial> verbosity level=debug
bywaf> signal run=<command-run-id> verbosity level=debug
bywaf> signal run=<command-run-id> pause --hard
```

`cancel`, `end`, `kill`, `pause`, `resume`, and `stop` are convenience aliases
over the same signal/control path. `end` and `kill` are synonyms; both default
to cooperative `--soft`, and `--hard` force-terminates the affected process:

```text
bywaf> cancel job=<id>
bywaf> cancel pipeline=<id>
bywaf> end job=<id>
bywaf> kill --hard pipeline=<id>
bywaf> pause job=<id>
bywaf> pause --hard job=<id>
bywaf> pause run=<command-run-id>
bywaf> resume --listonly pipeline=<id>
bywaf> resume --listonly run=<command-run-id>
bywaf> stop --hard job=<id>
```

## Advanced Runtime Control

Most users should prefer the friendly commands above. `signal` is the explicit
runtime-control form for debugging, plugin development, and rare control
messages that do not yet have their own top-level verb. Its main value is
auditability: the database records the exact control payload requested and the
plugin or framework response.

For example, these friendly commands:

```text
bywaf> pause run=7
bywaf> end --hard job=3
```

map to explicit control requests like:

```text
bywaf> signal run=7 pause --soft
bywaf> signal job=3 end --hard
```

For plugin-specific messages, the explicit form is the normal route because the
plugin owns the meaning of the action:

```text
bywaf> signal run=7 prune targets=192.168.1.0/24
bywaf> signal run=7 verbosity level=quiet
```

The resulting audit trail shows the requested selector, action, strength
(`--soft` or `--hard`), supplied arguments, and whether the receiver applied,
ignored, or rejected the request.

`jobs` remains as a convenience alias for `job list`, and `pipelines` remains
as a convenience alias for `pipeline list`.

# Database and Event Model

Bywaf stores events in SQLite. The default database is:

```text
.bywaf/bywaf.sqlite3
```

SQLite is used in WAL mode. Inserts are committed immediately; there is no
separate document-style save step. On shutdown, Bywaf checkpoints the WAL using
`PRAGMA wal_checkpoint(TRUNCATE)` so WAL contents are folded back into the main
database file.

List known event topics:

```text
bywaf> topics
```

Show the last 25 events, or choose an explicit tail size:

```text
bywaf> events
bywaf> events tail
bywaf> events tail last=50
```

Show recent events for a topic:

```text
bywaf> event host.found
bywaf> event port.open
```

List command runs:

```text
bywaf> runs
```

Show events by command run or pipeline:

```text
bywaf> event run=1
bywaf> event pipeline=1
bywaf> event serial=<durable-serial>
```

Save a database snapshot:

```text
bywaf> save db=snapshot.sqlite3
```

Save an encrypted snapshot:

```text
bywaf> save --encrypt db=snapshot.sqlite3
```

Inspect or maintain the active database:

```text
bywaf> db status
bywaf> db path
bywaf> db checkpoint
bywaf> db vacuum
```

Create a fresh database and switch the active session to it:

```text
bywaf> db new
bywaf> db new --file=client.sqlite3
bywaf> db new --encrypt --file=client.sqlite3
bywaf> db new --force --file=client.sqlite3
```

Without `--file`, `db new` creates a timestamped database under `.bywaf/db/`.
With `--file`, it refuses to overwrite an existing file. Add `--force` to move
the existing database and SQLite sidecar files to timestamped `.bak-*` names
before creating the new DB. `--encrypt` forces SQLCipher encryption and prompts
twice for a passphrase.

The session variable `db.encryption=sqlcipher` makes `db new` encrypted by
default:

```text
bywaf> vars db.encryption=sqlcipher
bywaf> db new
```

Convert the active database in place:

```text
bywaf> db encrypt
bywaf> db rekey
bywaf> db decrypt
```

`db encrypt` converts the active plaintext database to SQLCipher and prompts
twice for a new passphrase. `db rekey` changes the passphrase for an encrypted
database. `db decrypt` exports the active encrypted database back to plaintext
SQLite after an explicit `YES` confirmation.

Switch to another database:

```text
bywaf> load db=snapshot.sqlite3
```

If the database is encrypted, Bywaf prompts for its passphrase when loading it.
Passphrases are kept in process memory only and are not written to config or
history files.

# Projects

A project is a named working directory with its own database, config, and
history:

```text
~/.bywaf/projects/<name>/bywaf.sqlite3
~/.bywaf/projects/<name>/config.toml
~/.bywaf/projects/<name>/history.bywaf
```

Start in an existing project, or create one before startup:

```text
bywaf project=client-a
bywaf --new project=client-b
bywaf --new --encrypt project=client-c
```

Manage projects from the REPL:

```text
bywaf> project list
bywaf> project info
bywaf> project new name=client-b
bywaf> project use name=client-b
```

Switching projects changes the active database, config, and history path. Bywaf
refuses to switch while jobs are active because those jobs belong to the current
database. To deliberately hard-stop active jobs and switch anyway:

```text
bywaf> project use name=client-b --force
```

The forced stop is audited in the old project database before the switch.

# Resource Files

Bywaf keeps default state in:

```text
.bywaf/
```

Important files:

```text
.bywaf/bywaf.sqlite3
.bywaf/config.toml
.bywaf/history.bywaf
.bywaf/plugins/
```

Resource resolution rules are consistent:

```text
plugin=<name>   -> .bywaf/plugins/<name>
script=<name>   -> ./<name>
db=<name>       -> ./<name>
config=<name>   -> ./<name>
history=<name>  -> ./<name>
```

Explicit paths are used as filesystem paths for every resource type:

```text
./name
../name
~/name
/absolute/name
```

Examples:

```text
bywaf> load script=scan.bywaf
bywaf> load script=./scripts/scan.bywaf
bywaf> save config=session.toml
bywaf> load config=session.toml
bywaf> save history=session-history.bywaf
bywaf> load history=session-history.bywaf
```

# Variables

List variables:

```text
bywaf> vars
```

Set a variable:

```text
bywaf> vars name=value
```

Secret-looking variable names such as `password`, `pw`, `token`, `secret`,
`api-key`, `authorization`, and `cookie` are stored as secret references in the
normal variable store. `vars`, command history, and audit-friendly displays
show `<redacted>` plus an HMAC fingerprint instead of the plaintext:

```text
bywaf> vars ssh_probe.password=client-password
ssh_probe.password=<redacted> fingerprint=hmac-sha256:...
```

Credential-aware commandlets resolve those references through the framework
secret API at run time. This keeps the normal variable store redacted while
still allowing commandlets such as `ssh_probe`, `ldap_probe`, `smb_probe`, and
`shodan_lookup` to authenticate.

Secrets are persisted in the active database so they survive restart. If the
database is encrypted, they are protected by that database encryption at rest.
If the database is plaintext, Bywaf prints a warning before storing the secret
there.

Show one variable:

```text
bywaf> vars name
```

Common examples:

```text
bywaf> vars http_probe.cookie-file=/tmp/cookies.txt
bywaf> vars history.timestamp-format=%Y-%m-%d %H:%M:%S %Z
bywaf> vars hostscanner.targets=192.168.1.1-255
bywaf> hostscanner
```

Use a commandlet context to make short variable assignments target that
commandlet:

```text
bywaf> use hostscanner
bywaf> vars targets=192.168.1.1-255
bywaf> use global
```

For commandlets that opt into variable defaults, explicit command-line
arguments take precedence over commandlet variables, and commandlet variables
take precedence over built-in defaults. For example,
`hostscanner 127.0.0.1` ignores `hostscanner.targets`, while `hostscanner`
falls back to it.

Save variables:

```text
bywaf> save config=config.toml
```

Load variables:

```text
bywaf> load config=config.toml
```

Config files are TOML tables containing session variables. Legacy JSON config
files can still be loaded for compatibility.

# History

Every non-empty REPL command is appended to:

```text
.bywaf/history.bywaf
```

History lines are stored as commands followed by a timestamp comment:

```text
hostscanner 127.0.0.1  # 2026-05-12 10:15:30 EDT
```

The `history` command shows only commands from the current REPL invocation,
with timestamps displayed first for easier scanning:

```text
bywaf> history
2026-05-17 10:00:00 EDT  plugins
```

Limit session history by timestamp with `since=` and `until=`. Unqualified
values default to `time:` and use `yyyymmdd[HH[MM[SS]]]`:

```text
bywaf> history since=20260517 until=20260518
bywaf> history since=time:202605171000 until=time:202605171059
```

The persistent history file can be viewed with the OS commandlets:

```text
bywaf> cat .bywaf/history.bywaf
bywaf> less .bywaf/history.bywaf
```

The persistent history file stays script-friendly: timestamps are stored after
commands as comments, so history lines can be copied into a script file.

Change the timestamp format:

```text
bywaf> vars history.timestamp-format=%Y/%m/%d %H:%M:%S %Z
```

# Scripts

Scripts are text files with one command expression per line:

```text
# scan local host
hostscanner 127.0.0.1
portscanner --from-topic host.found
```

Blank lines and lines beginning with `#` are ignored. Inline comments are also
allowed after whitespace:

```text
plugins  # list loaded plugin providers
```

Run a script:

```text
bywaf> load script=scan.bywaf
```

# Bundled Commandlets

## os

`ls` lists local files:

```text
bywaf> ls
bywaf> ls bywaf/plugins
```

`cat` prints a local text file:

```text
bywaf> cat README.md
```

`less` opens the system `less` pager when running interactively:

```text
bywaf> less README.md
```

Use `/` to search inside `less`, arrow keys or paging keys to scroll, and `q` to
quit.

## discovery

`hostscanner` discovers live hosts with nmap:

```text
bywaf> hostscanner 127.0.0.1
bywaf> hostscanner 192.168.0.1-255
bywaf> hostscanner 192.168.1-3.1-255
```

It emits `host.found` events.

## network

`portscanner` scans hosts for open ports:

```text
bywaf> portscanner 127.0.0.1
bywaf> portscanner --ports 22,80,443 127.0.0.1
```

If `--ports` is omitted, nmap uses its normal default top-port behavior. It
emits `port.open` events.

Use listen mode to consume newly inserted hosts:

```text
bywaf> portscanner --listen
```

`ssh_probe` uses Paramiko for SSH service/auth probing and emits
`ssh.service`:

```text
bywaf> ssh_probe 127.0.0.1
bywaf> ssh_probe username=test password=test 127.0.0.1
```

`snmp_get` uses pysnmp to read one OID and emits `snmp.value`:

```text
bywaf> snmp_get community=public oid=1.3.6.1.2.1.1.1.0 127.0.0.1
```

## recon

`dns_lookup` uses dnspython and emits `dns.record` or `dns.error`:

```text
bywaf> dns_lookup example.com
bywaf> dns_lookup record-type=MX example.com
```

`shodan_lookup` uses the Shodan Python library. Set `SHODAN_API_KEY`, use
`api-key=...`, or set `vars shodan_lookup.api-key=...`.

```text
bywaf> shodan_lookup 8.8.8.8
bywaf> shodan_lookup mode=search apache country:US
```

## identity

`ldap_probe` uses ldap3 and emits `ldap.server`:

```text
bywaf> ldap_probe dc.example.test
bywaf> ldap_probe username='EXAMPLE\\user' password=secret dc.example.test
```

`smb_probe` uses Impacket and emits `smb.server`:

```text
bywaf> smb_probe 127.0.0.1
bywaf> smb_probe domain=EXAMPLE username=user password=secret dc.example.test
```

## http

`http_headers` performs HTTP HEAD requests and emits `http.headers` events:

```text
bywaf> http_headers example.com
bywaf> http_headers --ssl true example.com
```

`http_probe` probes HTTP endpoints and emits `http.endpoint` events:

```text
bywaf> http_probe https://example.com/
```

`webfin` fingerprints HTTP endpoints and emits `web.fingerprint` events:

```text
bywaf> http_probe https://example.com/ | webfin
bywaf> webfin https://example.com/
```

`nikto` wraps the Nikto web scanner through the framework process API, attaches
raw JSON output as an artifact, and emits
`nikto.finding`, `vulnerability.found`, and `vulnerability.potential` events:

```text
bywaf> nikto https://example.com/
bywaf> http_probe https://example.com/ | nikto
bywaf> http_probe https://example.com/ | webfin | nikto
```

`source=webfin` is available when Nikto receives mixed upstream input and you
want it to ignore plain `http.endpoint` events.

`eyewitness` wraps EyeWitness for web screenshots. It writes output under
`.bywaf/eyewitness/<run-id>` by default, or under `--output-dir` when supplied.
Screenshot files are also attached to the encrypted artifact store when the
active database is encrypted, or the plaintext artifact store otherwise.

```text
bywaf> eyewitness https://example.com/
bywaf> http_probe https://example.com/ | eyewitness
bywaf> eyewitness --output-dir=client-shots https://example.com/
```

For authorized session-aware testing, it can use cookies:

```text
bywaf> vars http_probe.cookie-file=/path/to/cookies.txt
bywaf> http_probe https://example.com/
bywaf> http_probe --firefox-profile ~/.mozilla/firefox/<profile>
```

## wireless

`wifi_scan` wraps a Kismet-style wireless scan. It writes logs under
`.bywaf/wireless/<run-id>` by default, attaches produced files to the paired
artifact store, and emits `wifi.network` plus `kismet.network` events from JSON
output when present.

```text
bywaf> wifi_scan interface=wlan0mon duration=60
bywaf> vars wifi_scan.interface=wlan0mon
bywaf> wifi_scan duration=120
```

## analysis

`finding_dedupe` normalizes vulnerability/finding events and emits deduplicated
finding lifecycle events: `finding.new`, `finding.duplicate`,
`finding.updated`, and `finding.merge_candidate`. It preserves the original
scanner output and points normalized findings back to their source events, so a
reporter plugin can later render tables from the normalized event stream.

```text
bywaf> nikto https://example.com/ | finding_dedupe
bywaf> finding_dedupe file=dedupe-summary.json
bywaf> finding_dedupe format=md file=findings.md
```

Exact matches use standardized identifiers such as CVE/CWE/GHSA/vendor IDs
when available, then target identity and stable evidence fingerprints. Fuzzy
text matching is only used as a low-confidence `finding.merge_candidate`.

`finding_report` renders normalized dedupe events or raw tool findings as a
table through the framework table provider. The columns are Finding name,
Description, Host(s) affected, CVE, Severity rating, and Recommendation.
`export=` writes the table to a file, infers the format from the suffix, and
attaches the report as an artifact.

```text
bywaf> finding_report
bywaf> finding_report source=tools
bywaf> finding_report export=findings.md
bywaf> finding_report export=findings.xlsx
```

`yara_scan` uses yara-python and emits `yara.match`:

```text
bywaf> yara_scan rule=webshells.yar shell.php
```

# Common Workflows

Scan one host for live status:

```text
bywaf> hostscanner 127.0.0.1
```

Scan one host for ports:

```text
bywaf> portscanner 127.0.0.1
```

Discover hosts and scan their ports:

```text
bywaf> hostscanner 192.168.0.1-255 | portscanner
```

Run discovery and port scanning in the background:

```text
bywaf> hostscanner 192.168.0.1-255 & | portscanner &
```

Probe HTTP services after port scanning:

```text
bywaf> hostscanner 127.0.0.1 | portscanner --ports 80,443 | http_probe
```

Fingerprint HTTP services after probing:

```text
bywaf> hostscanner 127.0.0.1 | portscanner --ports 80,443 | http_probe --method GET | webfin
```

Save the current database:

```text
bywaf> save db=scan-results.sqlite3
bywaf> save --encrypt db=scan-results.sqlite3
```

Save variables and session history:

```text
bywaf> save config=session.json
bywaf> save history=session.bywaf
```

# Troubleshooting

If `python` is not available, use `python3`:

```bash
python3 -m bywaf
```

If scanning fails with an nmap error, verify that `nmap` is installed and that
the selected Python nmap binding is available.

If socket creation is denied, the process may be running inside a sandbox or
without the privileges needed by the selected scan type.

If a command is unknown, check loaded commandlets:

```text
bywaf> cmds
```

If a plugin does not load, verify its directory structure and that it defines a
`plugin()` factory returning a commandlet.

SQLite WAL files such as `.sqlite3-wal` and `.sqlite3-shm` are normal. Bywaf
checkpoints the WAL on shutdown.

# Developer Notes

The main package layout is:

```text
bywaf/app.py          REPL and built-in commands
bywaf/runner.py       parsing, pipelines, foreground/background execution
bywaf/db.py           SQLite event store
bywaf/plugin.py       commandlet protocol and specs
bywaf/registry.py     plugin discovery and loading
bywaf/completion.py   prompt_toolkit/readline completion
bywaf/plugins/        bundled plugin providers
tests/                unit tests
```

Run tests:

```bash
python3 -m unittest discover -s tests
```

Run completion regressions only:

```bash
python3 -m unittest discover -s tests -p 'test_completion_regression.py'
```

The completion regression suite loads every default commandlet and verifies
that command names, binary `--flag` options, value-bearing `name=` arguments,
choice values, filespec values, `$variable` references, runtime selectors,
pipe-position command completion, and prompt-toolkit display labels stay
consistent.

Run the PTY-level readline Tab smoke tests only:

```bash
python3 -m unittest discover -s tests -p 'test_interactive_completion_smoke.py'
```

Those smoke tests launch the real REPL under `pexpect`, type partial commands,
send Tab, and verify the terminal text. They force `BYWAF_INPUT_READER=readline`
for deterministic PTY behavior; prompt-toolkit display behavior is covered by
the faster completion adapter tests.

Run user-facing script flows only:

```bash
python3 -m unittest tests.test_user_flows
python3 tests/scripts/run_user_flow.py tests/user_flows/basic_runtime.bywaf
```

User flows are ordinary `.bywaf` scripts with optional `# EXPECT:` and
`# EXPECT-EVENT:` assertions. They exercise real REPL/script commands from the
operator's point of view and double as executable examples.

Add a commandlet by defining a class with a `CommandSpec` and a `run()` method,
then expose it through a `plugin()` factory. Add bundled commandlets to
`bywaf/plugins/plugins.toml` when they should load by default.

Commandlets can declare completion metadata with `ArgumentSpec`,
`OptionSpec(..., completion=CompletionSpec(...))`, or an optional custom
`complete(context, args, prefix)` method. See `PLUGIN_AUTHOR_GUIDE.md` for a
walkthrough and a small working example.

# Reference

Useful built-ins:

```text
help [command]
plugins
cmds
vars [name=value]
history
job <list|show|cancel|end|kill>
pipeline <list|show|cancel|end|kill|attach>
signal <job=id|run=id|serial=id> <action> [--soft|--hard] [key=value ...]
cancel <job=id|pipeline=id|run=id>
end [--soft|--hard] <job=id|pipeline=id|run=id>
kill [--soft|--hard] <job=id|pipeline=id|run=id>
name <run=id|pipeline=id|job=id> [name text]
note [add] <run=id|pipeline=id|job=id> [text=note|file=path]
artifact <attach|list|remove|replace|save|search|verify> [artifact=id|run=id|pipeline=id|job=id] [file=path|dir=path]
search [--regexp] <name=text|filename=text|note=text|content=text> [artifact=id|run=id|pipeline=id|job=id] [since=time|until=time]
jobs
pipelines
runs
events [tail|--tail] [last=N]
topics
event <topic>
event job=<id>
event run=<id>
event pipeline=<id>
event serial=<id>
db <status|path|checkpoint|vacuum|new|encrypt|decrypt|rekey>
key <list|show|generate|import|export|remove|test>
bundle <create|add|list|show|seal|verify|export>
load plugin=<resource>
load script=<resource>
load db=<resource>
load config=<resource>
load history=<resource>
save db=<resource>
save --encrypt db=<resource>
save config=<resource>
save history=<resource>
prompt [pattern]
exit
```

Common event topics:

```text
host.found
port.open
http.headers
http.endpoint
job.requested
job.claimed
job.started
job.finished
job.failed
```
