"""Commandlet metadata decorators and base protocol types.

Provides the public commandlet decorator helpers, the commandlet protocol, and
the argparse-backed base class used by bundled and external plugins.

Used by:
- plugin authors: declare commandlet metadata and parse arguments.
- registry and runner: type commandlet implementations consistently."""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Protocol, TYPE_CHECKING, cast

from ..events import Event
from ..rendering import Table, render_console_table
from ..specs import ArgumentSpec, CommandSpec, CompletionSpec, OptionSpec

if TYPE_CHECKING:
    from .context import CommandContext


def commandlet(
    *,
    name: str,
    description: str,
    usage: str = "",
    examples: Sequence[str] = (),
    consumes: Sequence[str] = (),
    emits: Sequence[str] = (),
    capabilities: Sequence[str] = (),
):
    """Decorate a commandlet class with a `CommandSpec`.

    Use this with `@argument` and `@option` to keep plugin metadata readable
    without hand-writing a full `CommandSpec` block.
    """
    def decorate(cls):
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
            raise ValueError(f"{self.spec.name} requires {name} argument or {context.source}.{name} variable")
        return []


def split_var_values(value: str) -> list[str]:
    """Split comma and whitespace separated variable values."""
    return [part for chunk in value.split(",") for part in chunk.split() if part]


def format_table(rows: Sequence[Mapping[str, object] | Sequence[object]], columns: Sequence[str]) -> list[str]:
    """Return aligned text rows for small commandlet tables."""
    rendered = render_console_table(Table.from_rows(rows, columns))
    return rendered.splitlines() if rendered else []
