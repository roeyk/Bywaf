"""Compatibility imports for bundled plugin argument helpers.

Used by:
- bundled plugin providers and commandlets that publish or consume framework events.
"""


from __future__ import annotations

from bywaf.plugin.parsing import kv_to_args, reject_option_equals

__all__ = ["kv_to_args", "reject_option_equals"]
