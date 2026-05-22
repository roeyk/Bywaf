"""Bywaf package metadata.

Provides package-level version information and marks the source tree as the
importable `bywaf` package."""


__version__ = "0.11.0"

from .api import BywafSession

__all__ = ["BywafSession", "__version__"]
