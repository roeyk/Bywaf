"""Store protocol definitions for persistence abstractions.

Provides the stable `bywaf.stores` import facade for event, runtime, artifact,
maintenance, and variable store protocols.

Used by:
- tests and future backends: validate storage contracts.
- runner-adjacent code: express expected store capabilities.
"""

from __future__ import annotations

from .artifacts import ArtifactStoreProtocol
from .events import EventStoreProtocol
from .maintenance import MaintenanceStoreProtocol
from .maintenance import VariableStoreProtocol
from .runtime import RuntimeStoreProtocol

__all__ = [
    "ArtifactStoreProtocol",
    "EventStoreProtocol",
    "MaintenanceStoreProtocol",
    "RuntimeStoreProtocol",
    "VariableStoreProtocol",
]
