"""Bundled plugin package.

Provides the package namespace used by PluginRegistry to discover built-in
commandlet providers.

Used by:
- bundled plugin providers and commandlets that publish or consume framework events.

Public surface: re-exports the package API so callers can import the
subsystem without depending on internal module layout.
"""
