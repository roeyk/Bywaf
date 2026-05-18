"""YARA file scanner commandlet backed by yara-python."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugins._args import key_value_to_long_options
from bywaf.plugins.recon.dns_lookup import optional_module

DEFAULTS = {"rule": ""}
OPTION_KEYS = {"rule"}


@commandlet(
    name="yara_scan",
    description="Scan files with yara-python.",
    usage="yara_scan rule=rules.yar <file ...>",
    examples=("yara_scan rule=webshells.yar shell.php",),
    emits=("yara.match",),
    capabilities=("db.write:yara.match", "db.write:tool.error", "filesystem.read"),
)
@option("rule", "YARA rule file", completion="path")
class YaraScan(CommandletBase):
    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Compile a YARA rule file and scan files."""
        del input_events
        parser = self.parser()
        parser.add_argument("files", nargs="+")
        parser.add_argument("--rule", default=self.var_default(context, "rule", ""))
        parsed = parser.parse_args(key_value_to_long_options(args, OPTION_KEYS))
        yara = optional_module(context, "yara", "yara-python")
        if yara is None:
            return ()
        if not parsed.rule:
            raise ValueError("yara_scan requires rule=<path> or vars yara_scan.rule=<path>")
        context.audit_capability("filesystem.read")
        rules = yara.compile(filepath=str(Path(parsed.rule).expanduser()))
        for file_name in parsed.files:
            path = Path(file_name).expanduser()
            context.audit_capability("filesystem.read")
            for match in rules.match(str(path)):
                context.events.publish(
                    "yara.match",
                    {
                        "file": str(path),
                        "rule": str(getattr(match, "rule", match)),
                        "namespace": str(getattr(match, "namespace", "")),
                        "tags": list(getattr(match, "tags", []) or []),
                    },
                )
        return ()


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return YaraScan()
