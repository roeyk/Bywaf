"""Manifest-backed commandlet spec parsing helpers.

Used by:
- `@commandlet`: load command metadata from a sidecar TOML manifest.
- plugin checkers: compare decorator metadata against manifest declarations.
- completion/rendering paths: expose manifest arguments and defaults to users.
"""

from __future__ import annotations

import sys
import tomllib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Callable

from ...rendering import Table, render_console_table
from ...specs import ArgumentSpec, CommandSpec, CompletionSpec, OptionSpec


def manifest_path_for_function(func: Callable[..., Any]) -> Path:
    """Return the conventional sidecar manifest path for a plugin function.

    Called by: manifest-backed commandlet decorators when plugin authors keep
    most command metadata in TOML instead of Python decorator arguments.

    Package plugins use `bywaf.plugin.toml`; legacy single-file plugins use a
    sibling `*.plugin.toml` file.
    """
    module = sys.modules.get(func.__module__)
    module_file = getattr(module, "__file__", None)
    if not module_file:
        raise ValueError(f"{func.__name__} must be defined in a module with a manifest")
    path = Path(module_file)
    package_manifest = path.with_name("bywaf.plugin.toml")
    if path.name == "__init__.py" or package_manifest.exists():
        return path.with_name("bywaf.plugin.toml")
    return path.with_suffix(".plugin.toml")


def manifest_name_for_function(func: Callable[..., Any], path: Path) -> str:
    """Return the conventional manifest commandlet name for a plugin function.

    Called by: manifest-backed decorator paths after locating the sidecar. A
    package manifest may describe several commandlets by function name; a
    legacy `name.plugin.toml` sidecar derives the commandlet name from the file.
    """
    if path.name == "bywaf.plugin.toml":
        return func.__name__
    return path.stem.removesuffix(".plugin")


def spec_from_manifest(path: str | Path, commandlet_name: str) -> CommandSpec:
    """Build a CommandSpec from one commandlet row in a TOML manifest.

    Called by: the commandlet decorator when manifest-backed commandlets need
    framework metadata without duplicating every field in Python.
    """
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    row = manifest_commandlet_row(data, commandlet_name)
    # Database actions are nested in the manifest but flat in CommandSpec, so
    # normalize that subtable before constructing the public command metadata.
    database = row.get("database", {})
    database_actions = database.get("actions", {}) if isinstance(database, dict) else {}
    # CommandSpec is the public metadata consumed by registry, runner,
    # completion, help text, plugin checking, and docs generation. Keep this
    # constructor visibly parallel to the manifest fields so contract drift is
    # easy to spot during code review.
    return CommandSpec(
        name=commandlet_name,
        description=str(row.get("description") or ""),
        usage=str(row.get("usage") or ""),
        examples=tuple(str(item) for item in row.get("examples", ()) if isinstance(item, str)),
        options=tuple(option_spec_from_manifest(item) for item in row.get("options", ()) if isinstance(item, dict)),
        arguments=tuple(argument_spec_from_manifest(item) for item in row.get("arguments", ()) if isinstance(item, dict)),
        consumes=tuple(str(item) for item in row.get("consumes", ()) if isinstance(item, str)),
        emits=tuple(str(item) for item in row.get("emits", ()) if isinstance(item, str)),
        capabilities=tuple(str(item) for item in row.get("capabilities", ()) if isinstance(item, str)),
        database_actions=tuple(
            action for action in ("view", "write", "manage") if bool(database_actions.get(action))
        ) if isinstance(database_actions, dict) else (),
        provider_variables=tuple(str(item) for item in row.get("provider_variables", ()) if isinstance(item, str)),
        secret_provider_variables=tuple(str(item) for item in row.get("secret_provider_variables", ()) if isinstance(item, str)),
    )


def manifest_args_from_toml(path: str | Path, commandlet_name: str) -> tuple[dict[str, Any], ...]:
    """Return raw manifest argument rows for argparse-only fields like nargs.

    Called by: `CommandletBase.parser()` to preserve runtime parser settings
    that are not part of the public `ArgumentSpec` surface.
    """
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    row = manifest_commandlet_row(data, commandlet_name)
    return tuple(item for item in row.get("arguments", ()) if isinstance(item, dict))


def manifest_commandlet_row(data: Mapping[str, Any], commandlet_name: str) -> Mapping[str, Any]:
    """Return one commandlet manifest table by name.

    Called by: all manifest-to-spec helpers in this module before they parse
    commandlet-specific fields.
    """
    rows = data.get("commandlets", ())
    if not isinstance(rows, list):
        raise ValueError("manifest commandlets must be a sequence")
    # Manifest sidecars may describe multiple commandlets; select by the public
    # commandlet name so shared plugin packages can keep one manifest file.
    for row in rows:
        if isinstance(row, Mapping) and row.get("name") == commandlet_name:
            return row
    raise ValueError(f"manifest does not declare commandlet: {commandlet_name}")


def option_spec_from_manifest(row: Mapping[str, Any]) -> OptionSpec:
    """Build an OptionSpec from a manifest option table.

    Called by: `spec_from_manifest()` for public metadata and by registry
    manifest parsing when it needs the same `OptionSpec` contract.
    """
    name = str(row["name"])
    completion = row.get("completion")
    # Manifest `type` names become OptionSpec value_type strings. The actual
    # parser callable is selected later by `manifest_option_cast()`.
    return OptionSpec(
        name=name,
        description=str(row.get("description") or ""),
        default=manifest_default_to_string(row.get("default")),
        choices=tuple(str(item) for item in row.get("choices", ()) if isinstance(item, str)),
        completion=CompletionSpec(str(completion)) if isinstance(completion, str) else CompletionSpec(),
        secret=bool(row.get("secret", False)),
        value_type=str(row.get("type") or "str"),
    )


def argument_spec_from_manifest(row: Mapping[str, Any]) -> ArgumentSpec:
    """Build an ArgumentSpec from a manifest argument table.

    Called by: `spec_from_manifest()` to expose positional-argument metadata to
    completion, help, and plugin-check output.
    """
    completion = row.get("completion")
    # argparse uses `?` and `*` for optional positional arguments. Convert that
    # runtime parser detail into the simpler public ArgumentSpec.required flag.
    return ArgumentSpec(
        name=str(row["name"]),
        description=str(row.get("description") or ""),
        required=str(row.get("nargs") or "") not in {"?", "*"},
        completion=CompletionSpec(str(completion)) if isinstance(completion, str) else CompletionSpec(),
    )


def manifest_default_to_string(value: Any) -> str | None:
    """Normalize manifest defaults into CommandSpec string metadata.

    Used by: option parsing in both plugin-command and registry-manifest paths.
    CommandSpec stores defaults for display/completion; argparse rehydrates
    typed values later through `manifest_option_default()`.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def manifest_option_default(option_spec: OptionSpec) -> Any:
    """Return a typed manifest default for argparse.

    Called by: commandlet parser construction when manifest-declared options
    provide defaults.
    """
    if option_spec.default is None:
        return None
    return manifest_option_cast(option_spec)(option_spec.default)


def manifest_option_cast(option_spec: OptionSpec):
    """Return a parser/cfg cast function for a manifest option type.

    Used by argparse setup and variable-backed default hydration to keep CLI
    values consistent with manifest type declarations.
    """
    value_type = option_spec.value_type
    if value_type == "int":
        return int
    if value_type == "optional-int":
        return optional_manifest_int
    if value_type == "float":
        return float
    if value_type == "bool":
        return parse_manifest_bool
    return str


def optional_manifest_int(value: str | int | None) -> int | None:
    """Parse optional integer manifest values.

    Used by: `manifest_option_cast()` for options that accept an empty value as
    an unset integer.
    """
    if value in (None, ""):
        return None
    return int(value)


def parse_manifest_bool(value: str | bool) -> bool:
    """Parse bool-like manifest/CLI values.

    Used by: `manifest_option_cast()` so TOML defaults and CLI values share the
    same permissive boolean spelling rules.
    """
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "on"}


def kv_args_to_options(args: Sequence[str], option_names: set[str]) -> list[str]:
    """Convert `key=value` option args into argparse `--key=value` args."""
    # Only manifest-declared option names are rewritten. Positional arguments
    # containing `=` must pass through unchanged for the commandlet parser.
    converted: list[str] = []
    for arg in args:
        key, separator, value = arg.partition("=")
        if separator and key in option_names:
            converted.append(f"--{key}={value}")
        else:
            converted.append(arg)
    return converted


def option_dest(name: str) -> str:
    """Return a Python attribute-safe option destination.

    Used by: argparse setup when manifest option names contain dashes but the
    parsed namespace must expose underscore-safe Python attributes.
    """
    return name.replace("-", "_")


def split_var_values(value: str) -> list[str]:
    """Split comma and whitespace separated variable values.

    Used by: variable-backed option hydration when one stored variable supplies
    a lightweight list of argument values.
    """
    # This is deliberately simple and shell-agnostic; quoted parsing belongs in
    # the command parser, while variables are treated as lightweight lists.
    return [part for chunk in value.split(",") for part in chunk.split() if part]


def format_table(rows: Sequence[Mapping[str, object] | Sequence[object]], columns: Sequence[str]) -> list[str]:
    """Return aligned text rows for small commandlet tables.

    Used by: commandlet helpers that need framework table rendering without
    depending on REPL display modules.
    """
    rendered = render_console_table(Table.from_rows(rows, columns))
    return rendered.splitlines() if rendered else []
