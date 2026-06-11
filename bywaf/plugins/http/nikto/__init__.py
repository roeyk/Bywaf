"""Nikto wrapper commandlet.

Provides a bundled plugin implementation and CommandSpec metadata for the
external Nikto scanner.

Consumes:
- `http.endpoint` or `web.fingerprint` events, or explicit URL arguments.

Emits:
- `nikto.finding` for parsed Nikto records.
- `vulnerability.found` and `vulnerability.potential` compatibility events.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option, parse_bool
from .findings import (
    extract_finding_records,
    finding_identifiers,
    normalize_findings,
)
from .process import nikto_argv, run_target
from .targets import (
    dedupe_targets,
    filter_http_by_policy,
    nikto_targets,
    target_from_endpoint_event,
    target_from_webfin_event,
    target_payload_from_text,
)

__all__ = (
    "Nikto",
    "dedupe_targets",
    "extract_finding_records",
    "finding_identifiers",
    "filter_http_by_policy",
    "nikto_argv",
    "nikto_targets",
    "normalize_findings",
    "plugin",
    "target_from_endpoint_event",
    "target_from_webfin_event",
    "target_payload_from_text",
)

DEFAULTS = {
    "binary": "nikto",
    "plugins": "",
    "silent": "false",
    "source": "all",
    "timeout": "300",
    "tuning": "",
}


@commandlet(
    name="nikto",
    description="Run Nikto against HTTP endpoints and emit normalized findings.",
    usage="nikto [options] [target ...]",
    examples=(
        "nikto https://example.test/",
        "http_probe https://example.test/ | nikto",
        "http_probe https://example.test/ | webfin | nikto source=webfin",
    ),
)
@option("binary", "Nikto executable", "nikto", completion="path")
@option("plugins", "Nikto plugin selector")
@option("silent", "suppress finding alerts", "false")
@option("source", "endpoint source", "all", ("all", "explicit", "webfin"))
@option("timeout", "seconds per target", "300")
@option("tuning", "Nikto tuning selector")
class Nikto(CommandletBase):
    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Run Nikto for explicit targets or upstream HTTP endpoint events."""
        parser = self.parser()
        parser.add_argument("targets", nargs="*")
        parser.add_argument("-s", "--silent", action="store_true", default=self.var_default(context, "silent", False, cast=parse_bool))
        parser.add_argument("--binary", default=self.var_default(context, "binary", "nikto"))
        parser.add_argument("--plugins", default=self.var_default(context, "plugins", ""))
        parser.add_argument("--source", choices=("all", "explicit", "webfin"), default=self.var_default(context, "source", "all"))
        parser.add_argument("--timeout", type=float, default=self.var_default(context, "timeout", 300, cast=float))
        parser.add_argument("--tuning", default=self.var_default(context, "tuning", ""))
        parsed = parser.parse_args(args)

        targets = filter_http_by_policy(
            context,
            nikto_targets(parsed.targets, input_events, parsed.source),
        )
        if not targets:
            context.events.publish(
                "tool.error",
                {
                    "tool": "nikto",
                    "severity": "warning",
                    "message": "no HTTP endpoints selected for Nikto scan",
                    "source": parsed.source,
                },
            )
            return ()

        for target in targets:
            context.raise_if_cancelled()
            run_target(context, parsed, target)
        return ()


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return Nikto()
