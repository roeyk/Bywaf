"""Bywaf package metadata.

Provides package-level version information and marks the source tree as the
importable `bywaf` package.

Used by:
- Bywaf application code and tests that import this public module surface.

Public surface: re-exports the package API so callers can import the
subsystem without depending on internal module layout.
"""


__version__ = "0.13.0"

from .api import BywafSession

# Re-export only the stable embedding API and package version at top level.
__all__ = ["BywafSession", "__version__"]
