"""Minimal native Bywaf plugin skeleton.

Use this when one small commandlet is enough. For vulnerability/CVE logic,
prefer the multi-file native_vulnerability skeleton instead.
"""

from bywaf.plugin import Commandlet, commandlet


@commandlet
def example_minimal(context, cfg, input_events):
    """Keep small plugins simple; put real work in this function."""
    # This commandlet is standalone, so it does not consume pipeline input.
    del input_events

    # Place tiny native plugin logic here. `cfg.target` comes from the manifest
    # and already includes CLI args, stored plugin vars, defaults, and type
    # conversion.
    context.output(f"observed {cfg.target}")
    yield {"target": cfg.target, "status": "observed"}


def plugin() -> Commandlet:
    """Factory used by Bywaf plugin loading."""
    return example_minimal
