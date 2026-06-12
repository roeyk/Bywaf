"""Public commandlet metadata decorators.

Used by:
- plugin authors: decorate class-based commandlets and manifest-backed
  functions.
- plugin checker tests and docs: verify the supported authoring API.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Callable, TypeVar, cast, overload

from ...specs import ArgumentSpec, CommandSpec, CompletionSpec, OptionSpec
from .base import normalize_completion
from .manifest import FunctionCommandlet

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
        """Attach the commandlet specification to the decorated class."""
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
        """Attach the commandlet specification to the decorated class."""
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
        """Attach the commandlet specification to the decorated class."""
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
