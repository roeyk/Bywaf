"""Plugin manifest generation helpers.

Provides utilities to derive manifest metadata from plugin specs for bundled or
filesystem plugins.

Used by:
- plugin author tooling and tests: generate manifest files for signing/checking.
- catalog tooling: collect plugin metadata for trust workflows."""


from __future__ import annotations

import argparse
from pathlib import Path

from bywaf.plugin import Commandlet
from bywaf.registry import load_module_path, load_plugins, load_trigger_specs
from bywaf.specs import TriggerSpec
from bywaf.tools.plugin_check import analyze_plugin_source


def manifest_from_plugins(
    plugins: tuple[Commandlet, ...],
    triggers: tuple[TriggerSpec, ...] = (),
    *,
    native: bool = True,
    library_backed: bool = False,
    process_wrapped: bool = False,
    service: bool = False,
    inferred_capabilities: tuple[str, ...] = (),
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
        extra = inferred_capabilities if len(plugins) == 1 else ()
        lines.extend(commandlet_manifest_lines(plugin, inferred_capabilities=extra))
    for trigger in triggers:
        lines.extend(trigger_manifest_lines(trigger))
    return "\n".join(lines).rstrip() + "\n"


def commandlet_manifest_lines(
    plugin: Commandlet,
    *,
    inferred_capabilities: tuple[str, ...] = (),
) -> list[str]:
    """Return TOML lines for one commandlet."""
    spec = plugin.spec
    capabilities = tuple(sorted(set(spec.capabilities).union(inferred_capabilities)))
    lines = [
        "[[commandlets]]",
        f'name = "{escape_toml_string(spec.name)}"',
        "capabilities = [",
    ]
    lines.extend(f'  "{escape_toml_string(capability)}",' for capability in capabilities)
    lines.append("]")
    secret_options = [option.name for option in spec.options if option.secret]
    if secret_options:
        lines.append(f"secret_options = {toml_string_list(secret_options)}")
    if spec.provider_variables:
        lines.append(f"provider_variables = {toml_string_list(list(spec.provider_variables))}")
    if spec.secret_provider_variables:
        lines.append(f"secret_provider_variables = {toml_string_list(list(spec.secret_provider_variables))}")
    lines.append("")
    return lines


def trigger_manifest_lines(trigger: TriggerSpec) -> list[str]:
    """Return TOML lines for one provider-owned trigger."""
    lines = [
        "[[triggers]]",
        f'name = "{escape_toml_string(trigger.name)}"',
        f'topic = "{escape_toml_string(trigger.topic)}"',
        f'action_command = "{escape_toml_string(trigger.action_command)}"',
    ]
    if trigger.description:
        lines.append(f'description = "{escape_toml_string(trigger.description)}"')
    if trigger.action_mode != "service":
        lines.append(f'action_mode = "{escape_toml_string(trigger.action_mode)}"')
    if trigger.capability:
        lines.append(f'capability = "{escape_toml_string(trigger.capability)}"')
    if trigger.payload_equals:
        pairs = ", ".join(
            f'{escape_toml_string(key)} = "{escape_toml_string(value)}"'
            for key, value in trigger.payload_equals
        )
        lines.append(f"payload_equals = {{ {pairs} }}")
    if trigger.active_job:
        lines.append("active_job = true")
    if trigger.exclude_commandlets:
        lines.append(f"exclude_commandlets = {toml_string_list(list(trigger.exclude_commandlets))}")
    if not trigger.suppress_self_trigger:
        lines.append("suppress_self_trigger = false")
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
    parser.add_argument(
        "--infer-capabilities",
        action="store_true",
        help="add AST-inferred capabilities when the plugin exposes exactly one commandlet",
    )
    parser.add_argument("--output", "-o", help="write manifest to this path instead of stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for manifest generation."""
    args = build_parser().parse_args(argv)
    plugin_path = Path(args.plugin)
    module = load_module_path(plugin_path)
    plugins = load_plugins(module)
    triggers = load_trigger_specs(module)
    inferred_capabilities: tuple[str, ...] = ()
    if args.infer_capabilities:
        inferred_capabilities = analyze_plugin_source(plugin_path.parent).inferred_capabilities
    text = manifest_from_plugins(
        plugins,
        triggers,
        native=not (args.library_backed or args.process_wrapped),
        library_backed=args.library_backed,
        process_wrapped=args.process_wrapped,
        service=args.service,
        inferred_capabilities=inferred_capabilities,
    )
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
