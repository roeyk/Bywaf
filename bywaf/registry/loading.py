"""Plugin module loading helpers.

Provides factory invocation and Python module loading for bundled and external
plugin modules.

Used by:
- registry.core: loads bundled provider modules.
- registry.manifest: loads filesystem plugin packages after manifest checks.
- plugin tooling: imports plugins for metadata checks."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from ..plugin import Commandlet
from ..specs import TriggerSpec


def load_plugin(module: ModuleType) -> Commandlet:
    """Instantiate a plugin module via its required `plugin()` factory."""
    return load_plugins(module)[0]


def load_plugins(module: ModuleType) -> tuple[Commandlet, ...]:
    """Instantiate one or more commandlets from a plugin module."""
    multi_factory = getattr(module, "plugins", None)
    if multi_factory is not None:
        plugins = tuple(multi_factory())
        if not plugins:
            raise ValueError(f"{module.__name__}.plugins() returned no commandlets")
        return plugins
    factory = getattr(module, "plugin", None)
    if factory is None:
        raise AttributeError(f"{module.__name__} does not define plugin()")
    return (factory(),)


def load_trigger_specs(module: ModuleType) -> tuple[TriggerSpec, ...]:
    """Instantiate optional trigger specs from a provider plugin module."""
    factory = getattr(module, "triggers", None)
    if factory is None:
        return ()
    specs = tuple(factory())
    for spec in specs:
        if not isinstance(spec, TriggerSpec):
            raise TypeError(f"{module.__name__}.triggers() must return TriggerSpec objects")
    return specs


def load_plugin_path(path: Path) -> Commandlet:
    """Load an external plugin module from a concrete Python file path."""
    return load_plugins_path(path)[0]
def load_plugins_path(path: Path) -> tuple[Commandlet, ...]:
    """Load external commandlets from a concrete Python file path."""
    return load_plugins(load_module_path(path))


def load_module_path(path: Path) -> ModuleType:
    """Load an external Python module from a concrete file path."""
    if not path.exists():
        raise FileNotFoundError(f"{path} not found")
    module_name = f"bywaf_external_{path.parent.name}_{abs(hash(path))}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load plugin from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
