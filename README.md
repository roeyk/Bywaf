# Bywaf

This directory is a Python 3 rewrite scaffold for the original `src/`
code. It keeps the Metasploit-like command surface, but models work as
commandlets that publish and consume SQLite events.

## Run

```bash
cd bywaf
python3 -m bywaf --help
python3 -m bywaf repl
python3 -m bywaf run "hostscanner 127.0.0.1 | portscanner --ports 80,443"
python3 -m bywaf run "hostscanner 127.0.0.1 &"
python3 -m unittest discover -s tests
```

## Architecture

The important pieces are:

- `bywaf.db`: SQLite schema, WAL mode, transactional event publication, and polling subscriptions.
- `bywaf.plugin`: dataclasses and protocols for plugins, command specs, and command context.
- `bywaf.runner`: command parsing with structural pattern matching, foreground pipelines, and background processes.
- `bywaf.completion`: completion candidates for commands, plugin names, event names, and plugin options.
- `bywaf.plugins`: bundled safe example commandlets.
- `bywaf.varstore`: session variables populated from plugin defaults.

Bundled plugins are grouped under `bywaf/plugins/` and loaded from
`bywaf/plugins/plugins.json`. Adding a plugin file is not enough to load it by
default; add its dotted path to `default_plugins`.

The REPL supports `vars`, `topics`, `show <topic>`, `prompt [pattern]`,
`load plugin=<path>`, `load script=<path>`, `save db=<path>`,
`load db=<path>`, `save config=<path>`, `load config=<path>`,
`save history=<path>`, and `load history=<path>`.
Prompt patterns can use `%u`, `%h`, `%H`, `%m`, and `%T`.

Scripts are plain text files with one command expression per line. Blank lines
and lines starting with `#` are ignored.

The default state directory is `.bywaf/`. The default database is
`.bywaf/bywaf.sqlite3`, the default config file is `.bywaf/config.json`, and
the persistent REPL command history is appended to `.bywaf/history.bywaf`.
History lines are stored as commands followed by a `#` timestamp comment, so
they can be viewed with `cat .bywaf/history.bywaf` or `less .bywaf/history.bywaf`
and copied back into a script. The `history` command prints commands from the
current REPL invocation only. The history timestamp format defaults to
`%Y-%m-%d %H:%M:%S %Z` and can be changed with
`vars history.timestamp-format=<strftime format>`. Config files are JSON objects
containing session variables.

Resource names resolve consistently: `plugin=<name>` searches `.bywaf/plugins`,
while `script=<name>`, `db=<name>`, `config=<name>`, and `history=<name>` resolve
from the current directory. Explicit paths such as `./name`, `../name`, `~/name`,
and `/absolute/name` are used as filesystem paths for all resource types.

`hostscanner` and `portscanner` use nmap through a Python binding. The adapter
prefers `nmaplib`, then `python-nmap` (`import nmap`), then `nmapthon`, then
`libnmap`. A local `nmap` binary is still required by those libraries for real
scans. If `portscanner --ports ...` is omitted, nmap uses its normal default
top-port scan behavior.

`http_probe` consumes `port.open` events or explicit targets and emits
`http.endpoint` metadata: URL, scheme, status, final URL, selected headers,
title, and timing. For authorized session-aware testing, it can load cookies
from a Netscape cookie file or a Firefox profile:

```bash
vars http_probe.cookie-file=/path/to/cookies.txt
http_probe https://example.test/
http_probe --firefox-profile ~/.mozilla/firefox/<profile>
```

Each pipeline receives a `pipeline_id`, and each commandlet invocation receives
a `command_run_id`. Events store those IDs. With stage-level backgrounding:

```bash
hostscanner 192.168.0.1-255 & | portscanner &
```

`portscanner` automatically listens for `host.found` rows from the immediately
upstream `hostscanner` command run in that same pipeline. It does not consume
global `host.found` rows from unrelated scans.

## Plugin Contract

A plugin subclasses `Commandlet` and declares a `CommandSpec`. The `run()` method yields dictionaries. The runner inserts those dictionaries into SQLite as events.

```python
class Example(Commandlet):
    spec = CommandSpec(name="example", emits=("thing",))

    def run(self, context, args, input_events):
        yield {"value": args[0]}
```

Plugins can also read from the event database directly through `context.db`, or consume pipeline input supplied by the previous commandlet.

## Libraries Worth Considering

The rewrite uses only the standard library so tests are portable. For a production-grade tool, these libraries would reduce code size and edge cases:

- `prompt_toolkit`: richer REPL, history, completion menus, async-safe prompts, syntax highlighting.
- `click` or `typer`: less argparse and clearer command definitions.
- `pydantic`: plugin option validation and typed config loading.
- `rich`: terminal tables, status displays, tracebacks, and colored output without manual ANSI code.
- `pluggy` or Python entry points via `importlib.metadata`: external plugin discovery.
- `SQLAlchemy` or `dataset`: larger schema evolution, migrations, and less SQL boilerplate.
- `aiosqlite`: async event polling if the framework moves from processes to asyncio tasks.
- `python-nmap`: nmap wrapper for a real host/port scanner plugin.

## Notes From Original `src/`

The original project is Python 2, uses `imp`, `commands`, `raw_input`, `.iteritems()`, and global settings import side effects. The new package replaces those with `importlib`, `subprocess`/`socket`, dataclasses, explicit config, and testable functions.
