"""Runtime parser contract checks for plugin metadata.

Used by:
- maintainer tools, documentation/report generation, and validation scripts.
- tests and release checks that exercise developer-facing tooling.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Sequence

from bywaf.plugin import CommandletBase


def parser_contract_diagnostics(plugins: Sequence[Any], source_path: Path) -> list[dict[str, Any]]:
    """Return diagnostics for CommandSpec metadata that the argparse parser rejects."""
    diagnostics: list[dict[str, Any]] = []
    for plugin in plugins:
        if callable(getattr(plugin, "parse_manifest_args", None)):
            continue
        if getattr(type(plugin), "parser", None) is CommandletBase.parser:
            continue
        parser_factory = getattr(plugin, "parser", None)
        if not callable(parser_factory):
            continue
        try:
            parser = parser_factory()
        except Exception as exc:  # noqa: BLE001 - parser construction is plugin-owned.
            diagnostics.append(
                parser_diagnostic(
                    source_path,
                    "commandlet-parser-build-failed",
                    plugin.spec.name,
                    f"{plugin.spec.name} parser() failed: {exc}",
                    "Fix parser() so it can be constructed without runtime side effects; plugin_check validates parser metadata before accepting submissions.",
                )
            )
            continue
        if not isinstance(parser, argparse.ArgumentParser):
            diagnostics.append(
                parser_diagnostic(
                    source_path,
                    "commandlet-parser-build-failed",
                    plugin.spec.name,
                    f"{plugin.spec.name} parser() returned {type(parser).__name__}, expected argparse.ArgumentParser",
                    "Fix parser() so it returns an argparse.ArgumentParser instance.",
                )
            )
            continue
        parser_options, parser_arguments = argparse_contract(parser)
        missing_options = sorted(option.name for option in plugin.spec.options if f"--{option.name}" not in parser_options)
        missing_arguments = sorted(argument.name for argument in plugin.spec.arguments if argument.name not in parser_arguments)
        if missing_options:
            diagnostics.append(
                parser_diagnostic(
                    source_path,
                    "commandlet-option-parser-mismatch",
                    plugin.spec.name,
                    f"{plugin.spec.name} declares options not accepted by parser(): {', '.join(missing_options)}",
                    "Add matching parser.add_argument('--name', ...) entries, or remove/fix the @option/manifest option declarations.",
                )
            )
        if missing_arguments:
            diagnostics.append(
                parser_diagnostic(
                    source_path,
                    "commandlet-argument-parser-mismatch",
                    plugin.spec.name,
                    f"{plugin.spec.name} declares arguments not accepted by parser(): {', '.join(missing_arguments)}",
                    "Add matching parser.add_argument('name', ...) entries, or remove/fix the @argument/manifest argument declarations.",
                )
            )
    return diagnostics


def argparse_contract(parser: argparse.ArgumentParser) -> tuple[set[str], set[str]]:
    """Return long options and positional destinations accepted by one parser."""
    options: set[str] = set()
    arguments: set[str] = set()
    for action in parser._actions:
        if action.option_strings:
            options.update(option for option in action.option_strings if option.startswith("--"))
        elif action.dest != argparse.SUPPRESS:
            arguments.add(str(action.dest))
    return options, arguments


def parser_diagnostic(source_path: Path, code: str, commandlet: str, message: str, guidance: str) -> dict[str, Any]:
    """Build a plugin-check diagnostic dictionary."""
    return {
        "severity": "error",
        "code": code,
        "path": str(source_path),
        "line": 0,
        "message": message,
        "guidance": guidance,
        "commandlet": commandlet,
    }
