"""Compatibility facade for process artifact helpers.

The implementation lives in `bywaf.plugin.process.artifacts`; this module keeps
older imports such as `bywaf.plugin.process_artifacts` working while the process
subsystem moves under one package.
"""

from __future__ import annotations

from .process.artifacts import process_output_artifact_payload

__all__ = ["process_output_artifact_payload"]
