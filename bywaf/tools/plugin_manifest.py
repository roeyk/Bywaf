"""Generate starter plugin manifests from Python commandlet metadata."""

from __future__ import annotations

import argparse
from pathlib import Path

from bywaf.plugin import Commandlet
from bywaf.registry import load_plugins_path


def manifest_from_plugins(
    plugins: tuple[Commandlet, ...],
    *,
    native: bool = True,
    library_backed: bool = False,
    process_wrapped: bool = False,
    service: bool = False,
) -> str:
    """Return TOML text describing commandlets discovered from Python code."""
    lines = [
        "[plugin]",
        f"native = {toml_bool(native)}",
        f"library_backed = {toml_bool(library_backed)}",
        f"process_wrapped = {toml_bool(process_wrapped)}",
        f"service = {toml_bool(service)}",
        "",
    ]
    for plugin in plugins:
        lines.extend(commandlet_manifest_lines(plugin))
    return "\n".join(lines).rstrip() + "\n"


def commandlet_manifest_lines(plugin: Commandlet) -> list[str]:
    """Return TOML lines for one commandlet."""
    spec = plugin.spec
    lines = [
        "[[commandlets]]",
        f'name = "{escape_toml_string(spec.name)}"',
        "capabilities = [",
    ]
    lines.extend(f'  "{escape_toml_string(capability)}",' for capability in spec.capabilities)
    lines.append("]")
    secret_options = [option.name for option in spec.options if option.secret]
    if secret_options:
        lines.append(f"secret_options = {toml_string_list(secret_options)}")
    lines.append("")
    return lines


def toml_string_list(values: list[str]) -> str:
    """Return a compact TOML string list."""
    return "[" + ", ".join(f'"{escape_toml_string(value)}"' for value in values) + "]"


def toml_bool(value: bool) -> str:
    """Return TOML boolean text."""
    return "true" if value else "false"


def escape_toml_string(value: str) -> str:
    """Escape the minimal TOML basic-string characters used by manifests."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(prog="bywaf-plugin-manifest")
    parser.add_argument("plugin", help="path to a plugin.py file")
    parser.add_argument("--library-backed", action="store_true", help="mark plugin as using third-party Python libraries")
    parser.add_argument("--process-wrapped", action="store_true", help="mark plugin as wrapping external processes")
    parser.add_argument("--service", action="store_true", help="mark plugin as a long-running service provider")
    parser.add_argument("--output", "-o", help="write manifest to this path instead of stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for manifest generation."""
    args = build_parser().parse_args(argv)
    text = manifest_from_plugins(
        load_plugins_path(Path(args.plugin)),
        native=not (args.library_backed or args.process_wrapped),
        library_backed=args.library_backed,
        process_wrapped=args.process_wrapped,
        service=args.service,
    )
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
