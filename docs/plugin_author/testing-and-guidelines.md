# Plugin Testing And Guidelines

Testing expectations and practical implementation guidance for plugin authors.

## Testing a Plugin

Unit test the commandlet directly:

```python
from pathlib import Path
import tempfile
import unittest

from bywaf.db import EventStore
from bywaf.plugin import CommandContext
from plugin import FileInfo


class FileInfoTests(unittest.TestCase):
    def test_file_info_emits_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "sample.txt")
            path.write_text("hello")
            db = EventStore(Path(tmp, "db.sqlite3"))
            context = CommandContext(db, source="file_info")

            events = list(FileInfo().run(context, [str(path)], []))

            self.assertEqual(events[0]["size"], 5)
```

For framework-level tests, load the plugin through `PluginRegistry` and execute
it with `Runner`.

## Practical Guidelines

Keep commandlets small. A commandlet should usually do one thing and publish a
clear event topic.

Use structured events. Prefer:

```python
{"host": "127.0.0.1", "port": 80, "protocol": "tcp"}
```

over unstructured strings.

Declare `consumes` and `emits`. Those fields make `cmds`, help text, completion,
and pipeline behavior easier to understand.

Put expensive or long-running work behind clear options. Add `--timeout`,
`--limit`, or similar controls where appropriate.

Use `-s` or `--silent` for commandlets that print discovery alerts. The bundled
scanner commandlets use that convention. Plugins should emit console alerts
through the context instead of calling `print()` directly:

```python
context.alert("discovered host 127.0.0.1", silent=parsed.silent)
```

This writes a structured `console.alert` event for GUI/audit consumers and
mirrors the alert to stdout unless `silent` is true. Internally,
`context.alert()` first records `framework.console.alert.requested`; the
interpreter then validates that request, writes `console.alert`, and owns the
actual terminal output. This keeps multiprocessing output ordered and gives GUI
or web frontends a clean event stream to render.

Use `context.output()` for normal command output, such as listing rows or
printing a status message:

```python
context.output("scan complete")
context.table(
    [{"host": "127.0.0.1", "ports": 3}],
    ("host", "ports"),
)
```

`context.output()` records `framework.console.output.requested`; the interpreter
then writes a `console.output` event and owns the actual print. Advanced plugins
can call `context.request(topic, payload)` directly when Bywaf grows new
framework request types.

Prefer completion specs for common cases and custom completion only when the
generic specs are not expressive enough.
