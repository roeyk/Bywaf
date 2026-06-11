"""Compatibility facade for process execution helpers."""

from __future__ import annotations

from .process.exec import normalize_argv, popen_process_argv, run_process_argv

__all__ = ["normalize_argv", "popen_process_argv", "run_process_argv"]
