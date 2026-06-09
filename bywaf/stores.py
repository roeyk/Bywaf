"""Store protocol definitions for persistence abstractions.

Provides the stable `bywaf.stores` import facade for event, runtime, artifact,
maintenance, and variable store protocols.

Used by:
- tests and future backends: validate storage contracts.
- runner-adjacent code: express expected store capabilities.
"""

from __future__ import annotations

from .stores_artifacts import ArtifactStoreProtocol
from .stores_events import EventStoreProtocol
from .stores_maintenance import MaintenanceStoreProtocol
from .stores_maintenance import VariableStoreProtocol
from .stores_runtime import RuntimeStoreProtocol

__all__ = [
    "ArtifactStoreProtocol",
    "EventStoreProtocol",
    "MaintenanceStoreProtocol",
    "RuntimeStoreProtocol",
    "VariableStoreProtocol",
]
