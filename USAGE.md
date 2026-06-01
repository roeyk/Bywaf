# Bywaf Usage Guide

# Overview

Bywaf is a highly-auditable Python 3 commandlet framework for authorized web
application and network testing workflows. It presents a Metasploit-like
interactive shell, loads commandlets from plugins, and connects commandlets
through a SQLite-backed event bus.

The core idea is simple: one commandlet discovers something and publishes it as
an event; another commandlet consumes that event and publishes the next result.
For example, `hostscanner` can publish live hosts, `portscanner` can consume
those hosts and publish open ports, and HTTP commandlets can consume open ports
and probe web services.

Use Bywaf only on systems and networks where you have explicit authorization.

Common task examples are collected in [docs/FAQ.md](docs/FAQ.md).
The documentation roadmap starts at [docs/README.md](docs/README.md).
Evolving framework design notes are tracked in [docs/DESIGN.md](docs/DESIGN.md).
Maintainer signing-key policy is recorded in
[docs/KEY_MANAGEMENT.md](docs/KEY_MANAGEMENT.md).
Save/load/export/archive command semantics are explained in
[docs/SAVE_EXPORT_MODEL.md](docs/SAVE_EXPORT_MODEL.md).
Base capabilities, triggers, and audit/event topics are listed in
[docs/FRAMEWORK_SURFACE.md](docs/FRAMEWORK_SURFACE.md).
Core architectural references:

- [docs/TERMINOLOGY.md](docs/TERMINOLOGY.md) defines job, pipeline step, pipeline, events,
  topics, commandlets, plugins, capabilities, local IDs, and serials.
- [docs/RUNTIME_MODEL.md](docs/RUNTIME_MODEL.md) explains runtime entities, lifecycle,
  foreground/background execution, control signals, and variable snapshots.
- [docs/EVENT_MODEL.md](docs/EVENT_MODEL.md) explains event rows, topics, replay,
  framework requests, artifacts, notes, and provenance.
- [docs/CAPABILITY_MODEL.md](docs/CAPABILITY_MODEL.md) explains capability auditing,
  policy direction, and plugin integration types.
- [docs/SYSTEM_BLOCK_DIAGRAM.pdf](docs/SYSTEM_BLOCK_DIAGRAM.pdf) shows live runtime flow
  and durable data flow through the system.
- [docs/SYSTEM_DATAFLOW_DIAGRAM.pdf](docs/SYSTEM_DATAFLOW_DIAGRAM.pdf) focuses on command
  input, event, artifact, audit, request, and report data movement.

## Contents

- [Installation](#installation)
- [Starting Bywaf](#starting-bywaf)
- [REPL Basics](#repl-basics)
- [Commandlets](#commandlets)
- [Signing Keys](#signing-keys)
- [Evidence Bundles](#evidence-bundles)
- [Plugins](#plugins)
- [Pipelines](#pipelines)
- [Runtime Names](#runtime-names)
- [Framework Notes](#framework-notes)
- [Artifacts](#artifacts)
- [At-File Arguments](#at-file-arguments)
- [Variable Expansion](#variable-expansion)
- [Plans And Policy](#plans-and-policy)
- [Command Continuation And Sequences](#command-continuation-and-sequences)
- [Background Execution](#background-execution)
- [Database and Event Model](#database-and-event-model)
- [Projects](#projects)
- [Resource Files](#resource-files)
- [Variables](#variables)
- [History](#history)
- [Scripts](#scripts)
- [Bundled Commandlets](#bundled-commandlets)
- [Common Workflows](#common-workflows)
- [Troubleshooting](#troubleshooting)
- [Developer Notes](#developer-notes)
- [Reference](#reference)

# Installation

For OS-specific dependency blocks and package-build prerequisites, see
[INSTALL.md](INSTALL.md). The commands below are a quick summary.

During development, run Bywaf from the repository root:

```bash
cd bywaf
python3 -m bywaf --help
python3 -m bywaf
```

For an editable local install:

```bash
python3 -m pip install -e .
bywaf --help
bywaf
```

For a local pip package build:

```bash
scripts/build_pip_package.sh
python3 -m pip install dist/bywaf-0.12.1-py3-none-any.whl
bywaf --help
```

For normal Debian package installation from a release artifact:

```bash
sudo apt install ./bywaf_0.12.1-1_all.deb
bywaf --help
```

For maintainer/development Debian package builds from source, install the
Debian build dependencies and write artifacts under `dist/deb/`:

```bash
sudo apt install debhelper dh-python pybuild-plugin-pyproject python3-all python3-setuptools python3-prompt-toolkit
scripts/build_deb_package.sh
sudo apt install ./dist/deb/bywaf_0.12.1-1_all.deb
bywaf --help
```

For normal RPM package installation from a release artifact:

```bash
sudo dnf install ./bywaf-0.12.1-1.noarch.rpm
bywaf --help
```

For maintainer/development RPM package builds from source, install RPM build
tooling and write release artifacts under `dist/rpm/`:

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
job = session.job()
```

The host and port scanner commandlets use `nmap` through a Python adapter. A
local `nmap` binary and a supported Python binding are required for real scans.
The adapter prefers modules importing as `nmaplib`, then `nmap`, then
`nmapthon`, then `libnmap`; the `python-libnmap` package provides the
`libnmap` module.

## Dependency Summary

```text
nmap                       executable required for hostscanner and portscanner
python3-libnmap            packaged Python nmap adapter on Debian/RPM systems
nikto                      required for the nikto wrapper commandlet
eyewitness                 required for the eyewitness screenshot wrapper
kismet                     required for the wifi_scan wireless wrapper
prompt_toolkit             required for rich interactive REPL completion
python-libnmap/etc.        Python nmap adapter; Bywaf tries supported adapters
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
  python3-build python3-installer python3-prompt-toolkit nmap python3-libnmap \
  sqlcipher libsqlcipher-dev debhelper dh-python pybuild-plugin-pyproject \
  python3-all rpm nikto kismet
python3 -m pip install -e '.[plugins,reporting,signing,sqlcipher]'
python3 -m pip install python-libnmap python-nmap nmapthon
```

Fedora / RHEL-family:

```bash
sudo dnf install -y python3 python3-pip python3-setuptools python3-build \
  python3-installer python3-prompt-toolkit nmap python3-libnmap sqlcipher \
  sqlcipher-devel rpm-build nikto kismet
python3 -m pip install -e '.[plugins,reporting,signing,sqlcipher]'
python3 -m pip install python-libnmap python-nmap nmapthon
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
plugin's variables through that API. Shared provider variables are explicit via
`context.vars.get_provider(...)` for the immediate provider only; global
variables are explicit via `context.vars.get_global("name")`. When a commandlet
step starts, Bywaf snapshots the effective commandlet, immediate provider, and
global variables into the step's persisted variable snapshot. `event step=<id>`
displays the captured variables so steps remain auditable and reproducible even
when session variables change later.
Runtime entities have two identities: local IDs for interactive typing
(`job=12`, `step=1`, `pipeline=2`) and durable serials for audit/provenance.
Local IDs are stable inside the current database and are never reused there,
but they are not portable across replay/import into another database. Use
`event serial=<serial>` when you want to inspect by the durable identifier.
Explicit `plugin load=...` and `script load file=...` operations also receive
resource serials, so the load itself and the script commands it executed can be
reviewed later.

Plugins that need interpreter-owned actions use request events instead of
direct method calls. For example, a plugin can publish
`shell.prompt.requested`; the foreground REPL validates the request and records
either `shell.prompt.updated` or `framework.request.denied` for auditability.
Plugins declare intended capabilities through `@commandlet(...)`, which builds
the runtime `CommandSpec`; Bywaf records audit-only `plugin.capability.used` and
`plugin.capability.missing` events so operators can compare intended behavior
with actual behavior.
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
bywaf ls
bywaf cat README.md
bywaf 'hostscanner 127.0.0.1 | portscanner'
```

Simple commandlet invocations do not need quotes. Use quotes when the command contains
shell metacharacters such as `|`, `&`, `>`, or spaces that must be preserved
inside a single argument.

Use `exec` when you intentionally want to run an operating-system shell command
instead of a Bywaf commandlet:

```bash
bywaf exec 'ls -la | head'
```

# REPL Basics

The REPL prompt is:

```text
bywaf>
```

Set a custom prompt with `prompt <pattern>`. Prompt patterns support the older
`%u`, `%h`, `%H`, `%m`, and `%T` placeholders, plus `$u` for user, `$Y` year,
`$M` month, `$D` day, `$h` hour, `$m` minute, `$s` second, and `$Z` timezone.
Focus placeholders are `%p` for provider, `%c` for commandlet, `%P` for the
full active focus, and `%F` for a leading-space focus suffix when focus is set.

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
set
history
info
job <list|show|cancel|end|kill>
pipeline <list|show|cancel|end|kill>
signal <job=id|step=id|serial=id> <action> [--soft|--hard] [key=value ...]
cancel <job=id|pipeline=id|step=id>
end [--soft|--hard] <job=id|pipeline=id|step=id>
kill [--soft|--hard] <job=id|pipeline=id|step=id>
job
step
step <id|serial>
exec <shell-command>
<commandlet-pipeline>
events [tail|--tail] [last=N]
topics
db <status|path|checkpoint|vacuum|new|load|export|encrypt|decrypt|rekey>
event <id|topic|job=id|step=id|pipeline=id|serial=id>
plugin load=<resource> [--force]
config <load|save> file=<path> [--encrypt]
history [since=... until=...]
history <load|save> file=<path> [--encrypt]
script <load|save> file=<path> [--encrypt]
exit
```

`help <command>` shows the same help as `<command> --help` for commandlets.
Ctrl-C in the interactive shell asks whether to quit; answering yes exits
through the normal shutdown path, including the SQLite checkpoint.

Use `event` for runtime inspection and `audit` for evidence review:

| Need | Use | Why |
| --- | --- | --- |
| See recent runtime activity | `events` | Tails the live event bus. |
| Inspect one event and its job/step context | `event <id>` | Explains what emitted it, when, and under which runtime scope. |
| Debug a topic, job, step, pipeline, or serial | `event <selector>` | Stays close to raw event flow while keeping output readable. |
| Review assessment evidence | `audit show ...` | Presents selected records as an audit trail. |
| Inventory capability use | `audit list capabilities` | Compares declared capabilities with observed runtime behavior. |
| Hand off records | `audit export ...` | Writes portable JSONL, PDF, or SQLite audit output. |

The short rule is: `event` explains the bus; `audit` explains the assessment.

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
plugin specs. Commandlet option completion is contract-driven: normal
commandlet completions come from declared `@option` and `@argument` metadata,
not from emitted topics or parser internals. Other completion specs include
`topic`, `step`, `pipeline`, `job`, and `plugin`, so plugin authors can make
hand-typed commands much easier to complete correctly.
Runtime entity completions include prompt-toolkit metadata when available, such
as serial, status/source, event counts, and the current number of attached
artifacts.

Interactive shells use `prompt_toolkit` when a real terminal is available.
`Ctrl-Space` enters completion-selection mode by opening the menu and selecting
the first candidate. Then arrow keys move through candidates, `Enter` selects
the highlighted completion, and `Esc` returns to the command line. The
selection-mode key is configurable with `set completion.select-key=<key>` using
prompt-toolkit key names, because some desktop environments or terminal stacks
reserve `Ctrl-Space`. `set completion.wasd-selection=true` enables optional
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

Vulnerability and discovery plugins should prefer structured events over
bespoke prose. A plugin can emit facts, finding candidates, confirmations, and
artifacts without printing a mini-report. When a plugin is an intermediate
pipeline step, routine console output should stay quiet so the next step can
consume the event stream. The final step may render a concise summary, and
`report` is the preferred final renderer for normalized findings.

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
bywaf> set global.progress.min-interval-ms=250
bywaf> set global.progress.min-percent-delta=1
```

Audit logs are stored as SQLite events, but `audit` has a different job than
`event`:

| Need | Use | Why |
| --- | --- | --- |
| Runtime/provenance debugging | `event <id>` or `event <selector>` | Shows event-bus records and nearby job/step context. |
| Evidence review | `audit show ...` | Shows selected records as an assessment audit trail. |
| Capability inventory | `audit list capabilities` | Compares declared capabilities with observed runtime behavior. |
| Handoff/export | `audit export ...` | Writes portable JSONL, PDF, or SQLite output. |

The short rule is: `event` explains the bus; `audit` explains the assessment.

```text
bywaf> audit show topic=console.alert since=20260517 until=20260518
bywaf> audit list capabilities
bywaf> audit list capabilities plugin=nikto
bywaf> audit export file=audit.pdf since=step:<step-id>
bywaf> audit export --encrypt file=audit.sqlite3
bywaf> audit export --encrypt file=audit.pdf
```

Unqualified `since=` and `until=` audit bounds default to `time:`. Encrypted
SQLite audit exports use SQLCipher. Encrypted PDF export uses `pikepdf` when
available, otherwise the external `qpdf` command.

Inventory commands are schema-backed project views that answer operator
questions like "which hosts do we know about?", "which services are exposed?",
which web endpoints have we seen?", and "which WAFs were detected?" They
summarize accumulated target knowledge instead of showing runtime bookkeeping.

```text
bywaf> hosts
bywaf> services
bywaf> web
bywaf> wafs
bywaf> hosts --last
bywaf> services --new
bywaf> hosts pipeline=12
bywaf> services step=portscanner-...
bywaf> web job=latest
bywaf> wafs --last
```

`results` answers "what did that scan insert?" while inventory commands such as
`hosts`, `services`, `web`, and `wafs` answer "what does the project know now?"
They default to the accumulated project inventory and accept `job=`,
`pipeline=`, and `step=` when you want a narrower slice. Runtime/store views
such as `job`, `pipeline`, `step`, `event`, and `artifact` remain separate from
inventory commands.
When a selected result scope produced artifacts, `results` shows an `Artifacts`
section and the equivalent `artifact list ...` command for retrieving the
evidence bodies. If a wrapper cannot parse otherwise successful tool output,
`results` shows a `Tool problems` section and includes the raw-output artifact
reference when one is available.

`web` includes HTTP endpoint, path, screenshot, WAF, finding, and web
fingerprint facts, so `webfin` technology tags appear directly in the web
inventory and in `results`.

`http_headers` promotes common web hardening issues into findings, including
missing HSTS and X-Content-Type-Options, weak cookie attributes, informative
Server headers, and HTTPS-to-HTTP redirects.

Use `--last` on inventory commands to show the latest relevant producer scope.
Use `--new` to show facts from the selected or latest producer scope that were
not present in prior project inventory.

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
  git_expose_check
  nikto
  repo_exposure
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
```

Bundled plugins are listed in `bywaf/plugins/plugins.toml`. Adding a plugin file
is not enough to load it by default; add its dotted path to that config and add
or update its sidecar manifest, such as `bywaf/plugins/http/nikto.plugin.toml`.

External filesystem plugins are arbitrary local Python code. Bywaf refuses to
load them unless plugin catalog trust is verified or the operator explicitly
allows an unsigned development plugin. Use `--force` only when you want to
bypass every plugin trust check for reviewed local code:

```text
bywaf> plugin load=myplugin --force
```

Load a plugin from an explicit filesystem path:

```text
bywaf> plugin load=./plugins/myplugin --force
bywaf> plugin load=~/bywaf-plugins/myplugin --force
```

Startup plugin roots use the same policy. If you start Bywaf with
`--plugin-root` and `--plugin-config`, use `--allow-unsigned-plugins` for
unsigned development plugins:

```text
bywaf --plugin-root ~/.bywaf/plugins --plugin-config ~/.bywaf/plugins/plugins.toml --allow-unsigned-plugins
```

Filesystem catalog builds use the same entry layout as runtime loading. A
single-segment config entry such as `default_plugins = ["myplugin"]` points to
`~/.bywaf/plugins/myplugin/plugin.py` and
`~/.bywaf/plugins/myplugin/bywaf.plugin.toml`.

For reviewed external plugin trees, build and sign a catalog, then provide the
catalog and trusted public key at startup:

```text
bywaf --plugin-root ~/.bywaf/plugins \
  --plugin-config ~/.bywaf/plugins/plugins.toml \
  --plugin-catalog ~/.bywaf/plugins/plugin-catalog.signed.json \
  --plugin-catalog-key ~/.bywaf/plugins/plugin-catalog.pub.pem
```

Runtime catalog trust decisions are audited with
`plugin.catalog.verified`, `plugin.catalog.rejected`,
`plugin.catalog.entry.verified`, and `plugin.catalog.entry.rejected`.

`--allow-missing-plugin-keys` and `--allow-mismatched-plugin-keys` are narrower
developer bypasses for future signed external plugin catalogs when the trusted
verification key is absent or does not match the plugin signature.
`--plugin-manifest-key` supplies the trusted public key for signed
`bywaf.plugin.toml` files. `--allow-unsigned-plugin-manifests` is the narrow
development bypass for unsigned manifests. The legacy
`--force-plugins` startup flag is a hidden compatibility alias for
`--allow-untrusted-plugins`, which states the full tradeoff directly: load the
plugin even though Bywaf cannot verify its signature, signing key, or key match.
Official release public keys are reserved for `bywaf/keys/`; private signing
keys are maintainer release material and must stay outside the repository and
built packages. Official manifest-signing keys rotate annually with a staggered
60-day transition: publish the next public key, temporarily trust both keys,
switch signing to the next key, re-sign and release official plugin manifests,
then retire the old key. Revocation is reserved for suspected compromise or
emergency distrust. Use `--plugin-manifest-key` to trust a local or third-party
public key.

# Pipelines

Pipelines connect commandlets with `|`. Prefix the expression with `name:` to
name the pipeline without consuming commandlet arguments:

```text
bywaf> hostscanner 127.0.0.1 | portscanner
bywaf> client subnet scan: hostscanner 127.0.0.1 | portscanner
```

The runner executes each pipeline step in order. Events emitted by one
pipeline step are passed to the next pipeline step as input. Events are
also stored in SQLite with a pipeline ID and pipeline step ID.

This model allows downstream commandlets to consume only the output relevant to
the current pipeline, rather than every historical event in the database.

Attach a new background commandlet to an existing pipeline:

```text
bywaf> pipeline attach <pipeline-id> portscanner step=<producer-step-id> since=beginning
bywaf> pipeline attach <pipeline-id> http_probe since=now
```

The attach selectors are orthogonal:

- `<pipeline-id>` chooses the pipeline the new step joins.
- `step=<producer-step-id>` optionally narrows input to one upstream producer step.
- `since=beginning` replays matching historical events, then listens for new
  events.
- `since=now` ignores historical events and starts from the current event
  high-water mark.

If `step=` is omitted, the attached commandlet reads matching events from the
whole pipeline.

# Runtime Names

Name the current pipeline step with a step-local `name=` selector:

```text
bywaf> hostscanner 127.0.0.1 name=localhost sweep
```

Name or inspect runtime entities after they exist:

```text
bywaf> name step=<step-id> localhost sweep
bywaf> name pipeline=<pipeline-id> client subnet scan
bywaf> name job=<job-id> background listener
bywaf> name step=<step-id>
```

The explicit keyed form is `text=`, for example `name step=<id> text=localhost sweep`.

Assigned names appear in `step`, `pipeline`, and `job` listings.

# Framework Notes

Any pipeline step can include a framework-level `note=` selector. The runner
strips it before the commandlet receives arguments and records an audited
`note.attached` event with the job, pipeline, and step identities.

```text
bywaf> hostscanner 10.0.0.0/24 note=client-approved internal subnet
```

If `note=` is the last selector in a pipeline step, it consumes the rest
of that pipeline step without requiring quotes:

```text
bywaf> hostscanner targets note=scope approved | portscanner note=top ports
```

Review attached notes with the `note` commandlet. Output and file exports use
timestamp-first lines:

```text
bywaf> note step=<step-id>
bywaf> note pipeline=<pipeline-id>
bywaf> note job=<job-id> file=notes.txt
bywaf> note add step=<step-id> text=follow-up note
```

Notes are append-only. Adding another note creates another timestamped
`note.attached` event instead of replacing earlier notes.

# Artifacts

Artifacts are evidence files stored in a separate artifact database next to the
main database. They can be imported without external provenance, or attached to
a step, pipeline, or job when you know what produced or justifies them. Artifact
bodies are stored in the artifact database, not in the main event database.
If the main database is encrypted, the artifact database is encrypted with the
same session passphrase. If the main database is plaintext, the artifact
database is plaintext too. The main database stores timestamped provenance
events such as `artifact.imported`, `artifact.attached`, and
`artifact.exported`. Bywaf derives the artifact DB path from the active main DB
path so the two files remain an integrity pair; arbitrary artifact DB switching
is intentionally not exposed by default.

Start Bywaf with an encrypted database when you want SQLCipher-protected
artifact bodies:

```text
bywaf --encrypt
```

Import one or more files without attaching them to a step, pipeline, or job:

```text
bywaf> artifact import file=snapshot.html name='Landing page'
bywaf> artifact import file=headers.txt note=response headers
```

Attach existing artifacts, or import and attach files in one command:

```text
bywaf> artifact attach artifact=1 step=<step-id>
bywaf> artifact attach step=<step-id> file=snapshot.html name='Landing page'
bywaf> artifact attach serial=<step-or-pipeline-or-job-serial> file=snapshot.html
bywaf> artifact attach step=<step-id> file=snapshot.html file=headers.txt
bywaf> artifact attach pipeline=<pipeline-id> file=report.json note=initial report
```

List, search, export, and verify artifacts:

```text
bywaf> artifact list step=<step-id>
bywaf> artifact list topic=artifact.attached
bywaf> artifact cat 1
bywaf> artifact cat artifact=1 limit=4096
bywaf> artifact show 1
bywaf> artifact show artifact=1
bywaf> search step=<step-id> name=landing
bywaf> search step=<step-id> filename=snapshot.html
bywaf> search step=<step-id> content=csrf
bywaf> artifact search step=<step-id> --regexp filename='.*\\.png'
bywaf> artifact replace artifact=1 file=snapshot-v2.html
bywaf> artifact remove artifact=1
bywaf> artifact export artifact=1 file=snapshot.html
bywaf> artifact export serial=<artifact-serial> file=snapshot.html
bywaf> artifact export topic=artifact.attached dir=artifacts/
bywaf> artifact export step=<step-id> dir=artifacts/
bywaf> artifact verify pipeline=<pipeline-id>
```

Use `name=` for human-readable artifact labels; if omitted, the source filename
is used. The `search` commandlet, and its `artifact search` alias, search
artifact metadata quickly. `name=`, `filename=`, `note=`, and `content=` narrow
the search to artifact names, source filenames, notes, or decoded text contents. Add
`--regexp` to treat those field values as Python regular expressions. Any
commandlet whose main action is text search should follow the same `--regexp`
convention. `since=` and `until=` restrict matches by artifact creation time.
Use `artifact cat` to preview an artifact body in the terminal. Text-like
artifacts are decoded as text; binary artifacts are shown as a bounded hex dump.
Add `limit=<bytes>` to change the preview size.
Use `file=` when exporting exactly one artifact. Use `dir=` when exporting a set. If
`file=` matches multiple artifacts, Bywaf reports that clearly and asks you to
use `dir=` instead.
For `artifact attach`, `serial=` may refer to a step, pipeline, or job serial.
Artifact serials identify existing artifact rows for listing, searching,
exporting, and verifying; use `artifact=` when attaching an existing artifact
to step, pipeline, or job provenance.
Runtime detail views also surface attached artifacts directly:

```text
bywaf> job 7
bywaf> pipeline 12
bywaf> step 34
```

Each detail view prints compact artifact references plus the matching
`artifact list job=...`, `artifact list pipeline=...`, or `artifact list
step=...` command. Use `artifact show <id>` to inspect a single artifact's
provenance events, hash, storage metadata, and next commands.

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
bywaf> set host=192.168.1.1 192.168.1.2
bywaf> hostscanner $host
bywaf> hostscanner "$host"
bywaf> hostscanner '$host'
```

Resolution checks the exact variable name first, then the active commandlet
scope, then `global.`. For example, `$host` in `hostscanner` checks
`host`, `discovery/hostscanner.host`, and `global.host`. Variable
expansion is audited as `framework.variable.expanded`.

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
user>`. Suggested repairs, such as pruning out-of-scope targets for one step,
are audited as `plan.repair.applied` or `plan.repair.denied`.

Initial network policy variables:

```text
bywaf> set global.policy.network.allow=192.168.1.0/24
bywaf> set global.policy.network.deny=169.254.169.254/32,192.168.1.50
bywaf> set global.plan.required=true
```

The policy layer applies to the step being launched. Repairs do not mutate source
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
bywaf> set target=127.0.0.1; set; topics
```

Semicolons inside quotes are preserved as part of the argument text.

# Background Execution

Append `&` to background a commandlet or pipeline:

```text
bywaf> hostscanner 192.168.0.1-255 &
```

Normal commandlet execution is job-audited through the database. Foreground
commandlets run in-process but still record `job.requested`, `job.claimed`,
`job.started`, and `job.finished` or `job.failed`. Background job use the same
job lifecycle, but a worker process claims and runs the queued job. Foreground
management commands such as `db ...` and `job ...` run directly.

Pipeline-step backgrounding works inside pipeline:

```text
bywaf> hostscanner 192.168.0.1-255 & | portscanner &
```

In that example, `portscanner` listens for `host.found` rows created by the
immediately upstream `hostscanner` step in the same pipeline. It does not consume
unrelated `host.found` rows from older scans.

A pipeline groups one or more steps in the same command expression or attached
workflow. A step is one commandlet invocation inside that pipeline, such as the
specific `hostscanner` step or `portscanner` step. A job is the supervised
foreground/background execution lifecycle that runs one or more of those
commandlet invocations. Operationally, jobs are chained together into pipelines
by the steps they supervise; one job may contribute the whole chain, or multiple
jobs may contribute steps when commandlets are attached later. See
`docs/TERMINOLOGY.md` for the canonical definitions of job, pipeline, step, local
IDs, serials, events, and topics.

Show the currently active runtime entities:

```text
bywaf> info
```

List active jobs, or all jobs with an explicit active marker:

```text
bywaf> job
bywaf> job --all
bywaf> job --page
```

Show one job by local ID or durable job serial:

```text
bywaf> job <id>
bywaf> job <job-serial>
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
bywaf> pipeline
bywaf> pipeline --all
bywaf> pipeline --page
bywaf> pipeline <id>
bywaf> pipeline cancel <id>
bywaf> pipeline end <id>
bywaf> pipeline kill --hard <id>
```

`job`, `step`, and `pipeline` show active runtime state by default.
Use `--all` to include historical entries. These commands render table views
with local ID, durable serial, lifecycle state, names, timestamps, and an
`ARTIFACTS` column counting artifacts attached so far. Set
`set global.listing.active-format=long` to include the state timestamp in the
state column; set it to `short` for compact lifecycle labels. Use `--page` on
list-style commands such as `job`, `pipeline`, and `artifact list` to view
long output through the framework pager.

`watchdog` is Bywaf's default service-style runtime monitor. Its plugin also
provides a framework trigger:

```text
ON plugin.capability.used capability=network.connect job_id=<active job>
DO watchdog --session-service
```

Interactive sessions evaluate provider-owned triggers and stop any
session-scoped services during orderly shutdown. You can also run `watchdog`
manually to tune thresholds or test the current DB:

```text
bywaf> watchdog --once
bywaf> watchdog interval=10 timeout=300 stall-threshold=120 error-threshold=10 &
```

The watchdog emits `watchdog.timeout`, `watchdog.stalled`, and
`watchdog.error_rate` events when active job exceed the configured limits.
Trigger lifecycle events are also auditable: `framework.trigger.enabled`,
`framework.trigger.fired`, and `framework.trigger.disabled`. Fired events
include the source event ID that caused the trigger to fire.
Use `triggers` to list loaded provider-owned trigger rules and their current
cursors.

For live runtime control, `signal` is the canonical command for a concrete
receiver: a job, a pipeline step, or a `serial=` that resolves to one of those.
A pipeline is a grouping scope, not executing code, so it does not receive
plugin-domain signals directly. Use pipeline-aware commands such as `pause
pipeline=...` or `end --hard pipeline=...` when you want the framework to fan
out control over job associated with a pipeline. Framework-native signals such
as `pause`, `resume`, `stop`, `end`, and `kill` apply the existing framework
controls; plugin-domain signals such as `prune`, `mute`, `unmute`, and
`verbosity` are delivered for commandlets to apply or ignore.

```text
bywaf> signal step=<step-id> prune targets=192.168.1.0/24
bywaf> signal step=<step-id> mute
bywaf> signal serial=<step-or-job-serial> verbosity level=debug
bywaf> signal step=<step-id> verbosity level=debug
bywaf> signal step=<step-id> pause --hard
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
bywaf> pause step=<step-id>
bywaf> resume --listonly pipeline=<id>
bywaf> resume --listonly step=<step-id>
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
bywaf> pause step=7
bywaf> end --hard job=3
```

map to explicit control requests like:

```text
bywaf> signal step=7 pause --soft
bywaf> signal job=3 end --hard
```

For plugin-specific messages, the explicit form is the normal route because the
plugin owns the meaning of the action:

```text
bywaf> signal step=7 prune targets=192.168.1.0/24
bywaf> signal step=7 verbosity level=quiet
```

The resulting audit trail shows the requested selector, action, strength
(`--soft` or `--hard`), supplied arguments, and whether the receiver applied,
ignored, or rejected the request.

# Database and Event Model

Bywaf stores events in SQLite. The default database is:

```text
.bywaf/bywaf.sqlite3
```

Show database and artifact-store statistics:

```text
bywaf> db stats
```

This reports main database file sizes, table counts, event-topic counts,
runtime entity counts, and artifact database counts without performing database
maintenance. Use `db checkpoint` or `db vacuum` explicitly when you want those
maintenance operations.

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

Show detailed context for one event ID, or recent events for a topic:

```text
bywaf> event 25342
bywaf> event host.found
bywaf> event port.open
bywaf> event port.open host=192.168.50.163
bywaf> event port.open host=192.168.50.1,192.168.50.163 sort=host
bywaf> event port.open sort=protocol
```

`event <topic> field=value` filters by event payload fields. The `host=`
shortcut matches both top-level `host` payloads and common nested target host
fields such as `target.host`. Selector values are comma-separated OR lists;
values prefixed with `!` exclude matches from the selected set. Host-like
values also accept CIDR ranges and compact IPv4 last-octet ranges:

```text
bywaf> event port.open host=192.168.50.0/24,!192.168.50.1-128 port=80,443
```

Different selector keys are ANDed together. Use `sort=time` (default),
`sort=host`, `sort=protocol`, `sort=state`, `sort=topic`, or `sort=source` to
order displayed rows. `sort=transport` is an alias for `protocol`, and
`sort=status` is an alias for `state`.

Runtime selectors accept both local IDs and durable serials where the selector
has enough context. For example, `job 3` and `event job=3` use the current
database's local job ID; `job job-...` and `event job=job-...` use the durable
job serial. Prefer durable serials for notes, artifacts, logs, and anything
shared outside the current database.

Durable serials use a prefixed Crockford Base32 body. Tables show a short body
prefix to save terminal width, and selectors accept that short form when it is
unique:

```text
bywaf> job 01J8K2VQ
bywaf> step 01J8K2VQ
bywaf> pipeline 01J8K2VQ
bywaf> event serial=01J8K2VQ
```

List commandlet steps:

```text
bywaf> step
bywaf> step host=192.168.50.163
bywaf> job host=192.168.50.163
bywaf> pipeline host=192.168.50.163
bywaf> job since=120
bywaf> pipeline --new
bywaf> job sort=started
bywaf> job sort=-started
bywaf> pipeline sort=events
bywaf> step sort=started
```

Runtime view commands use selector syntax for sorting, not flags. Supported
runtime sort keys are command-specific. Sort keys are ascending by default; add
a leading `-` for descending order, for example `job sort=-started`. View
commands print the active sort order above the table and include the inverse
selector to type next. `pipeline --sort=events` is rejected; use
`pipeline sort=events`.

`job`, `pipeline`, and `step` accept the same payload-style filters as
`event`. They show runtime objects that have at least one associated event
matching the filter. `since=<id>` shows runtime objects created after a known
local ID for that command, for example `job since=120` or `step since=40`.
`--new` shows runtime objects created since the last time that runtime view was
checked and highlights the newest displayed row. Its cursor is stored as
operator-local filesystem state, not as project database events.

Show events by pipeline step or pipeline:

```text
bywaf> event step=1
bywaf> event pipeline=1
bywaf> event serial=<durable-serial>
```

Save a database snapshot:

```text
bywaf> db export file=snapshot.sqlite3
```

Save an encrypted snapshot:

```text
bywaf> db export --encrypt file=snapshot.sqlite3
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
bywaf> set db.encryption=sqlcipher
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
bywaf> db load file=snapshot.sqlite3
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
bywaf> project archive file=client-b-project.zip
bywaf> project archive file=client-b-project.bywaf-archive --encrypt
```

Switching projects changes the active database, config, and history path. Bywaf
refuses to switch while job are active because those job belong to the current
database. To deliberately hard-stop active job and switch anyway:

```text
bywaf> project use name=client-b --force
```

The forced stop is audited in the old project database before the switch.

`project archive` snapshots the active project's framework-owned files: the main
event database, paired artifact database, project config, project history, and
SQLite sidecars if present. It does not package arbitrary working-directory
files. Use evidence bundles or explicit artifact exports for curated client
deliverables; use `project archive` when you want to preserve or hand off the
whole Bywaf project state.

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
bywaf> script load file=scan.bywaf
bywaf> script load file=./scripts/scan.bywaf
bywaf> config save file=session.toml
bywaf> config load file=session.toml
bywaf> pref theme=classic
bywaf> pref prompt "$u@$h> "
bywaf> pref set identity.email=operator@example.com
bywaf> pref set identity.fullname="Example Operator"
bywaf> history save file=session-history.bywaf
bywaf> history load file=session-history.bywaf
```

# Variables

List variables:

```text
bywaf> set
```

Set a variable:

```text
bywaf> set name=value
```

Set an explicit secret variable:

```text
bywaf> set --secret network/ssh_probe.password=client-password
network/ssh_probe.password=[REDACTED#98a9bc10]
```

If the value is empty, Bywaf opens the configured secret input method and
records the command in history with a redacted value. The default interactive
method is a `[REDACTED]` block in the prompt; `getpass` uses a separate no-echo
prompt instead.

```text
bywaf> set --secret network/ssh_probe.password=
```

```text
bywaf> set secret.input-mode=block
bywaf> set secret.input-mode=getpass
bywaf> set secret.input-mode=plain
```

`plain` and `plaintext` allow visible typing in the prompt; after Enter, the
stored value is still replaced with `[REDACTED]` and a fingerprint.

Only explicit `--secret` assignments and commandlet options declared as secret
metadata are stored as secret references. Plain `set password=value` is an
ordinary variable. `set`, command history, and audit-friendly displays show
`[REDACTED]` plus an HMAC fingerprint for secret references instead of the
plaintext.

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
bywaf> set name
```

Common examples:

```text
bywaf> set http/http_probe.cookie-file=/tmp/cookies.txt
bywaf> set history.timestamp-format=%Y%m%d %H:%M:%S %Z
bywaf> set display.vars.color=auto
bywaf> set display.vars.name-color=cyan
bywaf> set display.vars.value-color=green
bywaf> set display.events.color=auto
bywaf> set display.events.key-color=green
bywaf> set display.history.color=auto
bywaf> set display.history.timestamp-color=green
bywaf> set display.help.color=auto
bywaf> set display.help.command-color=green
bywaf> set display/style.host=bold green
bywaf> set display/style.comment=dim color245
bywaf> set display/style.string=bold yellow
bywaf> set display/style.value=green
bywaf> set display/style.variable=cyan
bywaf> set display/style.table.header="bold white"
bywaf> set display/style.table.body=color250
bywaf> set display/style.table.index="bold color245"
bywaf> set display/style.table.active_row=bold
bywaf> set display/style.table.active_column="bold white"
bywaf> set display/style.report.heading="bold color39"
bywaf> set display/style.report.section="bold white"
bywaf> set display/style.report.label="bold color245"
bywaf> set display/style.serial=color245
bywaf> set display/style.job=color39
bywaf> set display/style.step=color39
bywaf> set display/style.pipeline=color39
bywaf> set display/style.finding.severity_class.urgent="bold red"
bywaf> set display/style.finding.severity_class.emergency="bold white bg-ansi:52"
bywaf> set display/style.finding.severity.critical="#dc2626"
bywaf> set display/style.finding.severity.high="bold red"
bywaf> set display.expansion=changed
bywaf> set discovery/hostscanner.host=192.168.1.1-255
bywaf> hostscanner
```

`display.vars.color` controls `set` output. `display.events.color` controls
`events`, `event <topic>`, `event <selector>`, and `event <id>` output.
`display.history.color` controls `history` output. `display.help.color`
controls the built-in `help` command list. These color modes accept `auto`,
`always`, or `never`. Name, value, event key, history timestamp, and help command
colors accept named colors such as `cyan`, `green`, `yellow`, `blue`,
`bold-green`, and `bold-yellow`; 256-color values such as `ansi:34`; truecolor
values such as `rgb:80,180,90`; and background forms such as `bg-ansi:52` and
`bg-rgb:80,0,0`. Event-list IDs are bright blue; detailed event section headers
are yellow; history timestamps and help commands are green.

Display styles use `display/style.<subject>`. Current terminal rendering
uses subjects such as `host`, `port`, `protocol`, `host.name`, `comment`,
`string`, `table.header`, `table.body`, `table.index`,
`table.active_row`, `table.active_column`, `report.heading`,
`report.section`, `report.label`, `finding.severity.high`, and
`finding.severity_class.urgent`. Runtime and provenance values can use subjects
such as `serial`, `job`, `step`, and `pipeline`. The `string` subject applies to
quoted spans in compact event output and live prompt input; `value` applies to
the value side of live `key=value` input when the value is not quoted;
`variable` applies to live assignment keys such as `A` in `set A=...` and
variable references such as `$A`. Report tables use table styles as baselines,
then more specific subjects such as `finding.title`, `finding.severity.high`, and
`finding.severity_class.urgent` override them inside matching cells. Style
values can combine attributes and colors, for example `bold green`, `dim
color245`, `rgb:80,180,90`, or quoted hex values such as `"#00ff00"`. Unquoted
`#` starts a REPL/script comment; quote or escape literal hashes.

Theme files may use explicit foreground/background tables when that is clearer
than a compact style string:

```toml
[variables."display/style.host"]
foreground = "cyan"
background = "transparent"
bold = true

[variables."display/style.finding.severity_class.emergency"]
foreground = "white"
background = "ansi:52"
bold = true
```

`background = "transparent"` means the subject does not set a background and an
outer style, such as a table or report style, can continue to show through. The
same structured fields can also be set directly, for example:

```text
bywaf> set display/style.host.foreground=cyan
bywaf> set display/style.host.background=transparent
bywaf> set display/style.host.bold=true
```

Theme presets are bundled named sets of display variables:

```text
bywaf> pref theme
themes: classic, default, mono
bywaf> pref theme=classic
saved pref theme=classic
```

Theme files are TOML or JSON mappings containing only `display.*` and
`display/style.*` variables. Loading a theme merges those variables into the
current session; it does not replace ordinary project variables.

```toml
[variables]
"display/style.variable" = "bright-cyan"
"display/style.string" = "bold yellow"
"display.expansion" = "changed"
```

Use `pref` for user-local defaults that should follow you across projects.
Preferences are intentionally limited to operator UX and identity/delivery
defaults: themes, prompt pattern, completion behavior, history formatting,
display expansion, `identity.email`, `identity.fullname`, `identity.username`,
and non-secret mail/report delivery defaults. They are stored in
`~/.bywaf/preferences.toml` by default and loaded when the REPL starts.
Preference keys are not plugin variables: they are not scoped through
provider/commandlet paths and commandlets do not receive them as scan options.

```text
bywaf> pref theme=classic
saved pref theme=classic
bywaf> pref prompt "$u@$h> "
saved pref prompt=$u@$h>
bywaf> pref set identity.email=operator@example.com
saved pref identity.email=operator@example.com
bywaf> pref set identity.fullname="Example Operator"
saved pref identity.fullname=Example Operator
bywaf> pref set mail.smtp.host=smtp.example.com
saved pref mail.smtp.host=smtp.example.com
```

Do not store SMTP passwords, API keys, tokens, or passphrases in preferences;
use the secret store for credential material.

```text
bywaf> pref set display.events.key-color=green
saved pref display.events.key-color=green
bywaf> pref set mail.smtp.password=secret
saved pref mail.smtp.password=secret
```

Command expansion previews are controlled by `display.expansion`:

```text
bywaf> set display.expansion=off
bywaf> event port.open host=$A
# no expansion preview

bywaf> set display.expansion=changed
bywaf> event port.open host=$A
expanded: event port.open host=192.168.50.163

bywaf> set display.expansion=on
bywaf> event port.open host=192.168.50.163
expanded: event port.open host=192.168.50.163
```

Variable expansion happens before commandlet execution. Expansion previews are
for operator visibility; secret references are redacted before preview output.

User preferences are separate from variables. The planned `pref` command is for
operator-owned defaults that should live under `~/.bywaf`, such as colors,
preferred pagers/editors, prompt style, and plugin UX defaults like
`plugins.portscanner.default-arguments`. Preferences should follow the user
across projects and should not be stored in project databases.

Use `set` for framework or plugin variables that affect the current project,
session, commandlet, or step. Variables can affect evidence-producing behavior,
so their effective values are snapshotted with command step and belong with the
project/audit context. If a future plugin wants to change a preference, it
should request a framework-mediated preference update for the user to approve;
plugins should not silently mutate `~/.bywaf/preferences.toml`.

Use a commandlet context to make short variable assignments target that
commandlet:

```text
bywaf> use hostscanner
bywaf> set host=192.168.1.1-255
bywaf> use global
```

For commandlets that opt into variable defaults, explicit command-line
arguments take precedence over commandlet variables, and commandlet variables
take precedence over built-in defaults. For example,
`hostscanner 127.0.0.1` ignores stored target variables, while `hostscanner`
falls back to `discovery/hostscanner.host` and then
`discovery/hostscanner.targets`.

Save variables:

```text
bywaf> config save file=config.toml
```

Load variables:

```text
bywaf> config load file=config.toml
```

Config files are TOML tables containing session variables. Legacy JSON config
files can still be loaded for compatibility.

# History

Every non-empty REPL command is added to in-memory session history. Bywaf does
not automatically append REPL commands to a clear-text history file.

History entries are stored as commands followed by a timestamp comment:

```text
hostscanner 127.0.0.1  # 20260512 10:15:30 EDT
```

The `history` command shows only commands from the current REPL invocation,
with timestamps displayed first for easier scanning:

```text
bywaf> history
20260517 10:00:00 EDT  plugins
```

Limit session history by timestamp with `since=` and `until=`. Unqualified
values default to `time:` and use `yyyymmdd[HH[MM[SS]]]`:

```text
bywaf> history since=20260517 until=20260518
bywaf> history since=time:202605171000 until=time:202605171059
```

Save session history explicitly when you need a file. Use `--encrypt` for
sensitive sessions:

```text
bywaf> history save file=session-history.bywaf --encrypt
bywaf> history load file=session-history.bywaf
```

Explicitly saved history files stay script-friendly: timestamps are stored
after commands as comments, so history lines can be copied into a script file.

Change the timestamp format:

```text
bywaf> set history.timestamp-format=%Y/%m/%d %H:%M:%S %Z
```

# Scripts

Scripts are text files with one command expression per line:

```text
# scan local host
hostscanner 127.0.0.1
portscanner --from step=<step-id> topic=host.found
```

Blank lines and lines beginning with `#` are ignored. Inline comments are also
allowed after whitespace:

```text
plugins  # list loaded plugin providers
```

Run a script:

```text
bywaf> script load file=scan.bywaf
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
bywaf> hostscanner host=127.0.0.1
bywaf> hostscanner 192.168.0.1-255
bywaf> hostscanner 192.168.1-3.1-255
```

`host=` accepts one host, DNS name, CIDR network, or IP range. Positional
targets remain accepted for quick one-offs. It emits `host.found` events.

## network

`portscanner` scans hosts for open ports:

```text
bywaf> portscanner 127.0.0.1
bywaf> portscanner port=22,80,443 host=127.0.0.1
bywaf> portscanner port=1-65535 host=192.168.50.0/24
bywaf> portscanner arguments="-Pn -sT" port=33169,33199 host=example.test
bywaf> portscanner --quiet port=22,80,443 host=127.0.0.1
```

If `port=` is omitted, nmap uses its normal default top-port behavior. It
emits `port.open` events.

Use `ports` to inspect scan results without rereading the raw event log:

```text
bywaf> ports
bywaf> ports sort=host
bywaf> ports sort=-host
bywaf> ports sort=port
bywaf> ports job=latest
bywaf> ports job=69
bywaf> ports host=192.168.50.0/24,!192.168.50.1-128 port=80,443
bywaf> ports all=true
```

By default, `ports` shows the latest portscanner job that produced open ports.
`sort=host` groups each host with its open ports; `sort=port` groups each port
with the hosts exposing it. Add a leading `-` for descending grouped views, for
example `ports sort=-port`. Use `all=true` only when you intentionally want
historical `port.open` events from older scans too.

`host=` accepts one host, a CIDR network, an IP range, or a comma/space-separated
host list. IP scan targets are passed through to nmap; DNS names are resolved
before scanning, printed, and recorded as `name.resolved` provenance events.
If `arguments=` includes `-4` or `-6`, the pre-scan DNS resolution keeps only
matching IPv4 or IPv6 addresses so the printed provenance matches what nmap
will scan. Use `--quiet` or `--silent` to suppress per-port console alerts while
still emitting `port.open` events.

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

`tcp_banner` connects to TCP services and emits `tcp.banner` events:

```text
bywaf> tcp_banner 127.0.0.1:22
bywaf> portscanner port=22,80 host=127.0.0.1 | tcp_banner
bywaf> tcp_banner mode=http-head 127.0.0.1:8080
```

Use `mode=banner` for services that speak first, such as SSH. Use
`mode=http-head` when you want Bywaf to send a minimal HTTP request before
reading the response.

## recon

`dns_lookup` uses dnspython and emits `dns.record` or `dns.error`:

```text
bywaf> dns_lookup example.com
bywaf> dns_lookup record-type=MX example.com
```

`shodan_lookup` uses the Shodan Python library. Set `SHODAN_API_KEY`, use
`api-key=...`, or set `set recon/shodan_lookup.api-key=...`.

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

`results` renders `http.headers` as a compact header summary, including missing
high-value security headers. Missing-header findings still flow through
`finding.candidate` for review.

`http_probe` probes HTTP endpoints and emits `http.endpoint` events:

```text
bywaf> http_probe https://example.com/
```

`git_expose_check` checks HTTP endpoints for exposed `.git/config` repository
metadata and promotes confirmed-looking exposures into `finding.candidate`:

```text
bywaf> git_expose_check target=https://example.com/
bywaf> http_probe https://example.com/ | git_expose_check
```

`repo_exposure` is an orchestrator commandlet for repository metadata exposure
checks. It currently runs the Git config exposure check and marks emitted
payloads with `family=repo_exposure` and `check=git_config`:

```text
bywaf> repo_exposure target=https://example.com/
bywaf> http_probe https://example.com/ | repo_exposure
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
`screenshotter` is the same wrapper under a more task-oriented command name.

```text
bywaf> eyewitness https://example.com/
bywaf> http_probe https://example.com/ | eyewitness
bywaf> eyewitness --output-dir=client-shots https://example.com/
bywaf> http_probe https://example.com/ | screenshotter
```

For authorized session-aware testing, it can use cookies:

```text
bywaf> set http/http_probe.cookie-file=/path/to/cookies.txt
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
bywaf> set wireless/wifi_scan.interface=wlan0mon
bywaf> wifi_scan duration=120
```

## analysis

`finding_dedupe` normalizes vulnerability/finding events and emits deduplicated
finding lifecycle events: `finding.new`, `finding.duplicate`,
`finding.updated`, and `finding.merge_candidate`. It preserves the original
scanner output and points normalized findings back to their source events, so a
reporter plugin can later render tables from the normalized event stream.
Some commandlets also emit `finding.candidate` automatically when a concrete
fact matches a small review-worthy rule, such as exposed Telnet or missing
high-value HTTP security headers.

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

`report` is the operator-facing finding inbox. It renders grouped open findings
from the latest pipeline that produced finding events, or from an explicit
pipeline, job, or step scope. Open means unreviewed plus confirmed. Use it when
you want to quickly see what finished work produced without manually querying
raw events. The heading always shows total, accepted, confirmed, deferred,
rejected, and unreviewed counts; the default view renders the groups that still
need attention during field work. After the
compact summary table, use `report <#>` or `report detail <#>` to show affected
resources, evidence snippets, sources, related artifacts, event/pipeline/step
provenance, and the latest update timestamp. Artifact references in report
detail include the matching `artifact list ...` command so the report stays
compact while still pointing at the stored evidence body. Reports print inline
by default; use `page=true` when you explicitly want a pager.

```text
bywaf> report
bywaf> report --last
bywaf> report --new
bywaf> report 1
bywaf> report detail 1-3
bywaf> report page=true
bywaf> report pipeline=1,2,3
bywaf> report job=7
bywaf> report step=12
bywaf> report status=all
bywaf> report status=confirmed
bywaf> report status=all --accepted-first
bywaf> report status=all --candidates-first
bywaf> report accept all pipeline=1
bywaf> report confirm 1 pipeline=1 note=validated manually
bywaf> finding confirm 1 pipeline=1
bywaf> report accept 1-3,7-9 pipeline=1
bywaf> report defer 4 pipeline=1 note=needs manual validation
bywaf> report reject 2 pipeline=1 note=false positive after retest
```

See [Finding And Report Model](docs/FINDING_MODEL.md) for the difference
between raw facts, finding candidates, deduplication, and report views.

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
bywaf> hostscanner 127.0.0.1 | portscanner port=80,443 | http_probe
```

Fingerprint HTTP services after probing:

```text
bywaf> hostscanner 127.0.0.1 | portscanner port=80,443 | http_probe --method GET | webfin
```

Save the current database:

```text
bywaf> db export file=scan-results.sqlite3
bywaf> db export --encrypt file=scan-results.sqlite3
```

Save variables and session history:

```text
bywaf> config save file=session.json
bywaf> history save file=session.bywaf
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
bywaf/command_parser.py commandlet and pipeline parsing
bywaf/runner.py       pipeline, foreground/background execution
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

Run the manual portscanner workflow smoke against a real nmap/libnmap
installation. The `.bywaf` version is a literal REPL script:

```bash
python3 -m bywaf
```

```text
bywaf> script load file=scripts/manual_portscanner_flow.bywaf
```

The Python wrapper runs the same style of workflow and also auto-selects the
first open-port host into `A` before checking `host=$A` filters:

```bash
python3 scripts/fake_telnet_service.py --host 127.0.0.1 --port 2323
python3 scripts/manual_portscanner_flow.py
python3 scripts/manual_portscanner_flow.py --target <authorized-host> --ports 80,443 --arguments "-Pn -sT"
```

Both workflows create a fresh database, scan the target, print `port.open` and
`name.resolved`, and exercise runtime listings.

For the `.bywaf` script, set `TARGET`, `PORTS`, and `NMAP_ARGS` before loading
it. `TARGET` can be a single host, DNS name, CIDR range, dash range, or
comma/space-separated list. `PORTS` can be comma-separated ports and ranges,
such as `22,80,443` or `1-60,80-90`.

Validate a filesystem plugin package outside the Bywaf interpreter:

```bash
python3 scripts/plugin_check.py path/to/plugin-dir
python3 scripts/plugin_check.py path/to/plugin-dir --strict-inference
python3 scripts/plugin_check.py path/to/plugin-dir --manifest-key manifest-signing.pub.pem --verify
python3 scripts/plugin_check.py path/to/plugin-dir --json
python3 scripts/plugin_check.py path/to/plugin.zip --temp-checkout --strict-inference --llm-feedback
python3 scripts/plugin_check.py --all
python3 -m bywaf.tools.plugin_manifest path/to/plugin-dir/plugin.py --infer-capabilities
python3 scripts/plugin_manifest_sign.py --manifest path/to/plugin-dir/bywaf.plugin.toml --private manifest-signing.pem --in-place
```

The checker validates manifest/code drift, reports AST-inferred capability
suggestions with file and line evidence, and can validate a plugin directory or
`.zip` submission from a copied temporary Bywaf checkout. The temp-checkout mode
is intended for reviewable LLM-generated submissions; it does not sandbox
hostile Python code. The manifest generator emits commandlets, secret options,
trigger specs, and, for single-commandlet plugins, can merge inferred
capabilities into a starter manifest. Filesystem plugin manifests must include
a non-empty `[plugin].version`; use `requires_bywaf` when the plugin depends on
a minimum Bywaf API version. Use `--all` as a maintainer check for every
bundled plugin listed in `bywaf.plugins/plugins.toml`.

The maintainer keeps private manifest-signing keys outside the repository.
Official public verification keys are packaged under `bywaf/keys/` when
released. Official manifest-signing keys rotate annually with a 60-day
staggered transition; official plugin manifests are re-signed and released with
the new key, and old keys are retired after the transition window. Revocation
is reserved for suspected compromise or emergency distrust.
`--plugin-manifest-key` can point at another trusted public key.

Build and verify a maintainer-side signed plugin catalog:

```bash
python3 scripts/plugin_catalog.py build --output dist/plugin-catalog.json
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

The catalog binds the reviewed bundled plugin list, plugin source hashes,
sidecar manifest hashes, traits, commandlets, capabilities, and secret options.
`--check-tree` proves the signed catalog still matches the files in the current
checkout.

Add a commandlet by defining a `CommandletBase` subclass decorated with
`@commandlet(...)`, `@argument(...)`, and `@option(...)`, then expose it through
a `plugin()` factory. Add bundled commandlets to `bywaf/plugins/plugins.toml`
when they should load by default. See `docs/plugin_author/README.md` for the plugin-author
documentation set and first-plugin workflow.

# Reference

Useful built-ins:

```text
help [command]
plugins
cmds
set [--secret] [name=value]
history
job <list|show|cancel|end|kill>
pipeline <list|show|cancel|end|kill|attach>
signal <job=id|step=id|serial=id> <action> [--soft|--hard] [key=value ...]
cancel <job=id|pipeline=id|step=id>
end [--soft|--hard] <job=id|pipeline=id|step=id>
kill [--soft|--hard] <job=id|pipeline=id|step=id>
name <step=id|pipeline=id|job=id> [name text]
note [add] <step=id|pipeline=id|job=id> [text=note|file=path]
artifact <import|attach|list|remove|replace|export|search|verify> [artifact=id|step=id|pipeline=id|job=id] [file=path|dir=path]
search [--regexp] <name=text|filename=text|note=text|content=text> [artifact=id|step=id|pipeline=id|job=id] [since=time|until=time]
job
pipeline
step
step <id|serial>
exec <shell-command>
<commandlet-pipeline>
events [tail|--tail] [last=N]
topics
event <topic>
event <id>
event job=<id>
event step=<id>
event pipeline=<id>
event serial=<id>
db <status|path|checkpoint|vacuum|new|load|export|encrypt|decrypt|rekey>
key <list|show|generate|import|export|remove|test>
bundle <create|add|list|show|seal|verify|export>
plugin load=<resource> [--force]
db load file=<resource>
db load file=<resource> --force
config load file=<resource>
pref [list|load|save] [file=<resource>]
pref set key=value [file=<resource>]
pref unset key [file=<resource>]
pref theme=<preset> [file=<resource>]
pref prompt <pattern> [file=<resource>]
history load file=<resource>
script load file=<resource>
db export file=<resource>
db export --encrypt file=<resource>
config save file=<resource>
config save file=<resource> --encrypt
history save file=<resource>
history save file=<resource> --encrypt
script save file=<resource>
script save file=<resource> --encrypt
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
