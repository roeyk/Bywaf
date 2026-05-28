"""Commandlet specification dataclasses.

Provides CommandSpec, OptionSpec, ArgumentSpec, and CompletionSpec metadata used
to describe plugin arguments, options, topics, and completions.

Used by:
- plugins and registry: publish commandlet metadata.
- runner, help, and completion: parse, document, and complete commandlets."""


from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class CompletionSpec:
    """Declarative completion behavior for an option or argument."""

    # `kind` is interpreted by the completion engine; `values` carries static
    # choices when kind="choice".
    kind: str = "none"
    values: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ArgumentSpec:
    """Metadata for one positional argument.

    Runtime validation still belongs to the commandlet's parser; this metadata
    is for help, introspection, and shell completion.
    """

    name: str
    description: str = ""
    required: bool = True
    completion: CompletionSpec = field(default_factory=CompletionSpec)


@dataclass(frozen=True, slots=True)
class OptionSpec:
    """Metadata for one long option exposed by a commandlet."""

    name: str
    description: str
    default: str | None = None
    choices: tuple[str, ...] = ()
    completion: CompletionSpec = field(default_factory=CompletionSpec)
    secret: bool = False


@dataclass(frozen=True, slots=True)
class CommandSpec:
    """Public commandlet contract consumed by help and completion."""

    # CommandSpec is metadata, not execution logic. Commandlets still build
    # their runtime parser inside run().
    name: str
    description: str
    usage: str = ""
    examples: tuple[str, ...] = ()
    options: tuple[OptionSpec, ...] = ()
    arguments: tuple[ArgumentSpec, ...] = ()
    consumes: tuple[str, ...] = ()
    emits: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    database_actions: tuple[str, ...] = ()
    provider_variables: tuple[str, ...] = ()
    secret_provider_variables: tuple[str, ...] = ()
