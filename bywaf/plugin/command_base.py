"""Commandlet protocol and argparse-backed base class.

Used by:
- plugin authors: subclass `CommandletBase` for class-based commandlets.
- manifest commandlet adapters: inherit the same parser/default helpers.
- registry and runner: type commandlet implementations through `Commandlet`.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING, Any, Protocol

from ..event import Event
from ..specs import CommandSpec, CompletionSpec
from .manifest_specs import split_var_values

if TYPE_CHECKING:
    from .context import CommandContext


def normalize_completion(completion: CompletionSpec | str | None) -> CompletionSpec:
    """Convert decorator completion shorthand into a `CompletionSpec`.

    Called by: `@argument` and `@option` decorators before building metadata.
    """
    if completion is None:
        return CompletionSpec()
    if isinstance(completion, CompletionSpec):
        return completion
    return CompletionSpec(completion)


class Commandlet(Protocol):
    """Runtime protocol every commandlet instance must satisfy.

    Implemented by: `CommandletBase` subclasses and function-backed commandlet
    adapters.
    Consumed by: registry and runner invocation paths.
    """

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
    """Convenience base class for commandlets that use argparse.

    Subclassed by: bundled and external class-based plugins, and
    `ManifestCommandlet` for manifest-backed plugins.
    """

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
