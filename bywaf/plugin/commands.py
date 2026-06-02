"""Commandlet metadata decorators and base protocol types.

Provides the public commandlet decorator helpers, the commandlet protocol, and
the argparse-backed base class used by bundled and external plugins.

Used by:
- plugin authors: declare commandlet metadata and parse arguments.
- registry and runner: type commandlet implementations consistently."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Callable, ClassVar, Protocol, TYPE_CHECKING, TypeVar, cast, overload

from ..event import Event
from ..specs import ArgumentSpec, CommandSpec, CompletionSpec, OptionSpec
from .manifest_specs import (
    format_table as format_table,
    key_value_args_to_options,
    manifest_arguments_from_manifest,
    manifest_name_for_function,
    manifest_option_cast,
    manifest_option_default,
    manifest_path_for_function,
    option_dest,
    parse_manifest_bool,
    spec_from_manifest,
    split_var_values,
)

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
        parser = ManifestArgumentParser(self.spec.name, self.spec.options)
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
                parser_kwargs.update({"nargs": "?", "const": True, "type": parse_manifest_bool, "metavar": "true|false"})
            else:
                parser_kwargs["type"] = manifest_option_cast(option_spec)
            parser.add_argument(f"--{option_spec.name}", **parser_kwargs)
        return parser.parse_args(key_value_args_to_options(args, option_names))


class ManifestArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that displays Bywaf `key=value` manifest options."""

    def __init__(self, prog: str, manifest_options: Sequence[OptionSpec]) -> None:
        super().__init__(prog=prog)
        self._bywaf_manifest_options = tuple(manifest_options)

    def format_help(self) -> str:
        """Render non-bool manifest options as `name=VALUE` in help text."""
        text = super().format_help()
        for option in self._bywaf_manifest_options:
            if option.value_type == "bool":
                continue
            metavar = option_dest(option.name).upper()
            text = text.replace(f"--{option.name} {metavar}", f"{option.name}={metavar}")
        return text


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
