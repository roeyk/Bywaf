"""Bywaf package metadata.

Provides package-level version information and marks the source tree as the
importable `bywaf` package."""


__version__ = "0.12.0"

from .api import BywafSession

# Re-export only the stable embedding API and package version at top level.
__all__ = ["BywafSession", "__version__"]
