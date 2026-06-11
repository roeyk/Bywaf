"""Public artifact storage facade.

Provides compatibility imports for artifact record types, the artifact store,
and paired artifact database helpers.

Used by:
- plugin services and command contexts: attach generated evidence.
- runtime artifact commands: list, show, export, verify, replace, and remove
  stored artifacts.
- tests and integrations: import artifact helpers from this stable module.
"""

from __future__ import annotations

from .artifact_records import ARTIFACT_SCHEMA, Artifact, ArtifactVerification
from .artifact_store import ArtifactStore, artifact_db_path, artifact_store_for_db

__all__ = [
    "ARTIFACT_SCHEMA",
    "Artifact",
    "ArtifactStore",
    "ArtifactVerification",
    "artifact_db_path",
    "artifact_store_for_db",
]
