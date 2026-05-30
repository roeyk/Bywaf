"""Commandlet metadata decorators and base protocol types.

Provides the public commandlet decorator helpers, the commandlet protocol, and
the argparse-backed base class used by bundled and external plugins.

Used by:
- plugin authors: declare commandlet metadata and parse arguments.
- registry and runner: type commandlet implementations consistently."""

from __future__ import annotations

import argparse
import sys
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Callable, ClassVar, Protocol, TYPE_CHECKING, TypeVar, cast, overload

from ..events import Event
from ..rendering import Table, render_console_table
from ..specs import ArgumentSpec, CommandSpec, CompletionSpec, OptionSpec

if TYPE_CHECKING:
    from .context import CommandContext

_T = TypeVar("_T")


@overload
def commandlet(target: Callable[..., Any], /) -> "FunctionCommandlet": ...


@overload
def commandlet(
    target: None = None,
    *,
    name: str,
    description: str,
    usage: str = "",
    examples: Sequence[str] = (),
    consumes: Sequence[str] = (),
    emits: Sequence[str] = (),
    capabilities: Sequence[str] = (),
    database_actions: Sequence[str] = (),
    provider_variables: Sequence[str] = (),
    secret_provider_variables: Sequence[str] = (),
) -> Callable[[_T], _T]: ...


def commandlet(
    target: Callable[..., Any] | None = None,
    *,
    name: str | None = None,
    description: str = "",
    usage: str = "",
    examples: Sequence[str] = (),
    consumes: Sequence[str] = (),
    emits: Sequence[str] = (),
    capabilities: Sequence[str] = (),
    database_actions: Sequence[str] = (),
    provider_variables: Sequence[str] = (),
    secret_provider_variables: Sequence[str] = (),
) -> Any:
    """Decorate a commandlet class or manifest-backed function.

    Bare `@commandlet` adapts a function into a manifest-backed commandlet.
    `@commandlet(...)` remains the lower-level class metadata decorator used
    with `@argument` and `@option`.
    """
    if target is not None:
        return FunctionCommandlet(target)

    def decorate(cls):
        if name is None:
            raise ValueError("class commandlet decorators require name=")
        # @option/@argument decorators run before @commandlet and stash metadata
        # on the class. Build the final immutable spec here.
        cls.spec = CommandSpec(
            name=name,
            description=description,
            usage=usage,
            examples=tuple(examples),
            options=tuple(getattr(cls, "_bywaf_options", ())),
            arguments=tuple(getattr(cls, "_bywaf_arguments", ())),
            consumes=tuple(consumes),
            emits=tuple(emits),
            capabilities=tuple(capabilities),
            database_actions=tuple(database_actions),
            provider_variables=tuple(provider_variables),
            secret_provider_variables=tuple(secret_provider_variables),
        )
        return cls

    return decorate


def option(
    name: str,
    description: str,
    default: str | None = None,
    choices: Sequence[str] = (),
    completion: CompletionSpec | str | None = None,
    secret: bool = False,
):
    """Decorate a commandlet class with one option metadata entry."""
    def decorate(cls):
        options = list(cast(tuple[OptionSpec, ...], getattr(cls, "_bywaf_options", ())))
        # Insert at the front so stacked decorators preserve source order in the
        # resulting CommandSpec.
        options.insert(
            0,
            OptionSpec(
                name,
                description,
                default,
                tuple(choices),
                normalize_completion(completion),
                secret,
            )
        )
        cls._bywaf_options = tuple(options)
        return cls

    return decorate


def argument(
    name: str,
    description: str = "",
    *,
    required: bool = True,
    completion: CompletionSpec | str | None = None,
):
    """Decorate a commandlet class with one positional argument metadata entry."""
    def decorate(cls):
        arguments = list(cast(tuple[ArgumentSpec, ...], getattr(cls, "_bywaf_arguments", ())))
        # Insert at the front for the same reason as options: decorator
        # execution order is bottom-up, but help text should read top-down.
        arguments.insert(
            0,
            ArgumentSpec(
                name,
                description,
                required=required,
                completion=normalize_completion(completion),
            )
        )
        cls._bywaf_arguments = tuple(arguments)
        return cls

    return decorate


def normalize_completion(completion: CompletionSpec | str | None) -> CompletionSpec:
    """Convert decorator completion shorthand into a `CompletionSpec`."""
    if completion is None:
        return CompletionSpec()
    if isinstance(completion, CompletionSpec):
        return completion
    return CompletionSpec(completion)


class Commandlet(Protocol):
    """Runtime protocol every commandlet instance must satisfy."""

    spec: CommandSpec

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ) -> Iterable[dict[str, Any]]:
        """Execute the commandlet and yield payload dictionaries."""
        ...


class CommandletBase:
    """Convenience base class for commandlets that use argparse."""

    spec: CommandSpec

    def database_actions_for_args(self, args: list[str]) -> tuple[str, ...]:
        """Return the DB action class this invocation intends to perform.

        Commandlets with mixed view/write/manage actions can override this to
        classify one argv before execution. The static spec remains the broad
        capability allowance used by policy checks.
        """
        del args
        return tuple(self.spec.database_actions)

    def parser(self) -> argparse.ArgumentParser:
        """Return an argparse parser named after this commandlet."""
        return argparse.ArgumentParser(prog=self.spec.name)

    def parse_args(self, args: list[str]) -> argparse.Namespace:
        """Parse commandlet arguments with the commandlet parser."""
        return self.parser().parse_args(args)

    def var_default(
        self,
        context: CommandContext,
        name: str,
        default: Any = None,
        *,
        cast=None,
        empty_is_none: bool = True,
    ) -> Any:
        """Return a commandlet variable value for use as an argparse default.

        This implements the Bywaf precedence rule: explicit CLI arguments
        override parser defaults, commandlet variables override code defaults,
        and code defaults are used last.
        """
        value = context.vars.get(name)
        if value is None or (empty_is_none and value == ""):
            return default
        if cast is None:
            return value
        try:
            return cast(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid value for {context.source}.{name}: {value}") from exc

    def values_or_var(
        self,
        context: CommandContext,
        values: Sequence[str],
        name: str,
        *,
        required: bool = False,
    ) -> list[str]:
        """Return CLI positional values or a split commandlet variable."""
        if values:
            return list(values)
        stored = context.vars.get(name)
        if stored:
            parsed = split_var_values(stored)
            if parsed:
                return parsed
        if required:
            raise ValueError(f"{self.spec.name} requires {name} argument or {context.vars.scope}.{name} variable")
        return []


class RunConfig:
    """Immutable per-run config produced from manifest, vars, and CLI args."""

    def __init__(self, values: Mapping[str, Any]) -> None:
        object.__setattr__(self, "_values", dict(values))
        for key, value in values.items():
            object.__setattr__(self, key, value)
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, name: str, value: Any) -> None:
        """Keep effective run config immutable after construction."""
        if getattr(self, "_frozen", False):
            raise AttributeError("run config is immutable")
        object.__setattr__(self, name, value)

    def __getattr__(self, name: str) -> Any:
        """Return dynamic config fields for generic commandlets."""
        try:
            return self._values[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def as_dict(self) -> dict[str, Any]:
        """Return a shallow copy for tests and debugging."""
        return dict(self._values)


class ManifestCommandlet(CommandletBase):
    """Base class for commandlets whose public interface comes from TOML."""

    spec: CommandSpec
    manifest_auto: ClassVar[bool] = True
    manifest_path: ClassVar[str | Path | None] = None
    manifest_name: ClassVar[str | None] = None
    manifest_arguments: tuple[dict[str, Any], ...] = ()

    def __init_subclass__(cls, **kwargs) -> None:
        """Populate manifest-backed metadata for subclasses by convention."""
        super().__init_subclass__(**kwargs)
        if cls.__dict__.get("manifest_auto") is False:
            return
        if "spec" in cls.__dict__:
            return
        path = cls.resolved_manifest_path()
        name = cls.resolved_manifest_name(path)
        cls.spec = spec_from_manifest(path, name)
        cls.manifest_arguments = manifest_arguments_from_manifest(path, name)

    @classmethod
    def resolved_manifest_path(cls) -> Path:
        """Return this subclass's manifest path."""
        if cls.manifest_path is not None:
            return Path(cls.manifest_path)
        module = sys.modules.get(cls.__module__)
        module_file = getattr(module, "__file__", None)
        if not module_file:
            raise ValueError(f"{cls.__name__} must define manifest_path")
        path = Path(module_file)
        if path.name == "__init__.py":
            return path.with_name("bywaf.plugin.toml")
        return path.with_suffix(".plugin.toml")

    @classmethod
    def resolved_manifest_name(cls, path: Path) -> str:
        """Return this subclass's manifest commandlet name."""
        if cls.manifest_name is not None:
            return cls.manifest_name
        if path.name == "bywaf.plugin.toml":
            return path.parent.name
        return path.stem.removesuffix(".plugin")

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ) -> Iterable[dict[str, Any]]:
        """Parse manifest-backed config and delegate to subclass behavior."""
        parsed = self.parse_manifest_args(context, args)
        cfg = RunConfig({dest: getattr(parsed, dest) for dest in vars(parsed)})
        return self.handle(context, cfg, input_events)

    def handle(
        self,
        context: CommandContext,
        cfg: RunConfig,
        input_events: Iterable[Event],
    ) -> Iterable[dict[str, Any]]:
        """Execute commandlet behavior with resolved config."""
        raise NotImplementedError

    def parse_manifest_args(self, context: CommandContext, args: list[str]) -> argparse.Namespace:
        """Parse CLI args after applying manifest defaults and stored vars."""
        parser = self.parser()
        option_names = {option.name for option in self.spec.options}
        for argument in self.manifest_arguments:
            kwargs: dict[str, Any] = {}
            if argument.get("nargs") is not None:
                kwargs["nargs"] = str(argument["nargs"])
            parser.add_argument(str(argument["name"]), **kwargs)
        for option_spec in self.spec.options:
            default = self.var_default(
                context,
                option_spec.name,
                manifest_option_default(option_spec),
                cast=manifest_option_cast(option_spec),
            )
            parser_kwargs: dict[str, Any] = {
                "dest": option_dest(option_spec.name),
                "default": default,
            }
            if option_spec.choices:
                parser_kwargs["choices"] = option_spec.choices
            if option_spec.value_type == "bool":
                parser_kwargs.update({"nargs": "?", "const": True, "type": parse_manifest_bool})
            else:
                parser_kwargs["type"] = manifest_option_cast(option_spec)
            parser.add_argument(f"--{option_spec.name}", **parser_kwargs)
        return parser.parse_args(key_value_args_to_options(args, option_names))


class FunctionCommandlet(ManifestCommandlet):
    """Internal adapter for function-style manifest commandlets."""

    manifest_auto = False

    def __init__(self, func: Callable[..., Iterable[dict[str, Any]] | None]) -> None:
        self.func = func
        manifest_path = manifest_path_for_function(func)
        manifest_name = manifest_name_for_function(func, manifest_path)
        self.spec = spec_from_manifest(manifest_path, manifest_name)
        self.manifest_arguments = manifest_arguments_from_manifest(manifest_path, manifest_name)

    def handle(
        self,
        context: CommandContext,
        cfg: RunConfig,
        input_events: Iterable[Event],
    ) -> Iterable[dict[str, Any]]:
        """Invoke the wrapped plugin function."""
        result = self.func(context, cfg, input_events)
        return result if result is not None else ()


def manifest_path_for_function(func: Callable[..., Any]) -> Path:
    """Return the conventional sidecar manifest path for a plugin function."""
    module = sys.modules.get(func.__module__)
    module_file = getattr(module, "__file__", None)
    if not module_file:
        raise ValueError(f"{func.__name__} must be defined in a module with a manifest")
    path = Path(module_file)
    if path.name == "__init__.py":
        return path.with_name("bywaf.plugin.toml")
    return path.with_suffix(".plugin.toml")


def manifest_name_for_function(func: Callable[..., Any], path: Path) -> str:
    """Return the conventional manifest commandlet name for a plugin function."""
    if path.name == "bywaf.plugin.toml":
        return func.__name__
    return path.stem.removesuffix(".plugin")


def spec_from_manifest(path: str | Path, commandlet_name: str) -> CommandSpec:
    """Build a CommandSpec from one commandlet row in a TOML manifest."""
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    row = manifest_commandlet_row(data, commandlet_name)
    database = row.get("database", {})
    database_actions = database.get("actions", {}) if isinstance(database, dict) else {}
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


def manifest_arguments_from_manifest(path: str | Path, commandlet_name: str) -> tuple[dict[str, Any], ...]:
    """Return raw manifest argument rows for argparse-only fields like nargs."""
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    row = manifest_commandlet_row(data, commandlet_name)
    return tuple(item for item in row.get("arguments", ()) if isinstance(item, dict))


def manifest_commandlet_row(data: Mapping[str, Any], commandlet_name: str) -> Mapping[str, Any]:
    """Return one commandlet manifest table by name."""
    rows = data.get("commandlets", ())
    if not isinstance(rows, list):
        raise ValueError("manifest commandlets must be a sequence")
    for row in rows:
        if isinstance(row, Mapping) and row.get("name") == commandlet_name:
            return row
    raise ValueError(f"manifest does not declare commandlet: {commandlet_name}")


def option_spec_from_manifest(row: Mapping[str, Any]) -> OptionSpec:
    """Build an OptionSpec from a manifest option table."""
    name = str(row["name"])
    completion = row.get("completion")
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
    """Build an ArgumentSpec from a manifest argument table."""
    completion = row.get("completion")
    return ArgumentSpec(
        name=str(row["name"]),
        description=str(row.get("description") or ""),
        required=str(row.get("nargs") or "") not in {"?", "*"},
        completion=CompletionSpec(str(completion)) if isinstance(completion, str) else CompletionSpec(),
    )


def manifest_default_to_string(value: Any) -> str | None:
    """Normalize manifest defaults into CommandSpec string metadata."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def manifest_option_default(option_spec: OptionSpec) -> Any:
    """Return a typed manifest default for argparse."""
    if option_spec.default is None:
        return None
    return manifest_option_cast(option_spec)(option_spec.default)


def manifest_option_cast(option_spec: OptionSpec):
    """Return a parser/cfg cast function for a manifest option type."""
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
    """Parse optional integer manifest values."""
    if value in (None, ""):
        return None
    return int(value)


def parse_manifest_bool(value: str | bool) -> bool:
    """Parse bool-like manifest/CLI values."""
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "on"}


def key_value_args_to_options(args: Sequence[str], option_names: set[str]) -> list[str]:
    """Convert `key=value` option args into argparse `--key=value` args."""
    converted: list[str] = []
    for arg in args:
        key, separator, value = arg.partition("=")
        if separator and key in option_names:
            converted.append(f"--{key}={value}")
        else:
            converted.append(arg)
    return converted


def option_dest(name: str) -> str:
    """Return a Python attribute-safe option destination."""
    return name.replace("-", "_")


def split_var_values(value: str) -> list[str]:
    """Split comma and whitespace separated variable values."""
    # This is deliberately simple and shell-agnostic; quoted parsing belongs in
    # the command parser, while variables are treated as lightweight lists.
    return [part for chunk in value.split(",") for part in chunk.split() if part]


def format_table(rows: Sequence[Mapping[str, object] | Sequence[object]], columns: Sequence[str]) -> list[str]:
    """Return aligned text rows for small commandlet tables."""
    rendered = render_console_table(Table.from_rows(rows, columns))
    return rendered.splitlines() if rendered else []
