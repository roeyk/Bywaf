"""Manifest-backed commandlet adapters.

Used by:
- bare `@commandlet` functions: adapted through `FunctionCommandlet`.
- advanced plugins: subclass `ManifestCommandlet` when TOML owns the public
  argument/option surface.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, ClassVar

from ..event import Event
from ..specs import CommandSpec, OptionSpec
from .command_base import CommandletBase
from .manifest_specs import (
    kv_args_to_options,
    manifest_args_from_toml,
    manifest_name_for_function,
    manifest_option_cast,
    manifest_option_default,
    manifest_path_for_function,
    option_dest,
    parse_manifest_bool,
    spec_from_manifest,
)

if TYPE_CHECKING:
    from .context import CommandContext


class RunConfig:
    """Immutable per-run config produced from manifest, vars, and CLI args.

    Constructed by: `ManifestCommandlet.run()` after parsing command arguments.
    Consumed by: manifest-backed commandlet functions and `handle()` methods.
    """

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
    """Base class for commandlets whose public interface comes from TOML.

    Subclassed by: manifest-backed bundled and filesystem plugins.
    Instantiated by: registry/plugin factories through normal commandlet
    construction paths.
    """

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
        cls.manifest_arguments = manifest_args_from_toml(path, name)

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
        return parser.parse_args(kv_args_to_options(args, option_names))


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
    """Internal adapter for function-style manifest commandlets.

    Constructed by: bare `@commandlet` in `command_decorators.commandlet()`.
    Consumed by: registry/runner through the standard `Commandlet` protocol.
    """

    manifest_auto = False

    def __init__(self, func: Callable[..., Iterable[dict[str, Any]] | None]) -> None:
        self.func = func
        manifest_path = manifest_path_for_function(func)
        manifest_name = manifest_name_for_function(func, manifest_path)
        self.spec = spec_from_manifest(manifest_path, manifest_name)
        self.manifest_arguments = manifest_args_from_toml(manifest_path, manifest_name)

    def handle(
        self,
        context: CommandContext,
        cfg: RunConfig,
        input_events: Iterable[Event],
    ) -> Iterable[dict[str, Any]]:
        """Invoke the wrapped plugin function."""
        result = self.func(context, cfg, input_events)
        return result if result is not None else ()
