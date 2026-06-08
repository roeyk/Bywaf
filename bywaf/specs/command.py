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
    """Declarative completion behavior for an option or argument.

    This represents a plugin-visible completion contract, not runtime
    validation.
    Constructed by: plugin decorators and manifest loaders.
    Used by: `BuiltinCompletionMixin.complete_by_spec()` and related completion
    providers to offer paths, topics, runtime selectors, static choices, or no
    completion.
    """

    # `kind` is interpreted by the completion engine; `values` carries static
    # choices when kind="choice".
    kind: str = "none"
    values: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ArgumentSpec:
    """Metadata for one positional argument.

    Runtime validation still belongs to the commandlet's parser; this metadata
    is for help, introspection, and shell completion.

    This represents the public shape of one positional argument.
    Constructed by: `@argument` decorators and manifest loading.
    Used by: help rendering, plugin checks, and completion providers.
    """

    name: str
    description: str = ""
    required: bool = True
    completion: CompletionSpec = field(default_factory=CompletionSpec)


@dataclass(frozen=True, slots=True)
class OptionSpec:
    """Metadata for one long option exposed by a commandlet.

    This represents the public shape of one commandlet option.
    Constructed by: `@option` decorators and manifest loading.
    Used by: help rendering, completion providers, secret handling, and plugin
    checks. Runtime value enforcement still belongs to plugin argparse.
    """

    name: str
    description: str
    default: str | None = None
    choices: tuple[str, ...] = ()
    completion: CompletionSpec = field(default_factory=CompletionSpec)
    secret: bool = False
    value_type: str = "str"


@dataclass(frozen=True, slots=True)
class CommandSpec:
    """Public commandlet contract for one commandlet.

    This is the framework's durable metadata view of a commandlet.
    Constructed by: plugin factories, decorators, and manifest inference.
    Used by: `PluginRegistry`, runner pipeline/topic checks, database policy,
    help, completion, and plugin-check tooling.
    """

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
