"""Library-backed Bywaf plugin skeleton.

Use this when a commandlet imports a third-party Python package in-process.
Declare `library_backed = true` in the manifest. Keep dependency failures
clear and user-facing.
"""

from bywaf.plugin import Commandlet, commandlet


# LLM Guardrail: bare @commandlet decorates the commandlet function, not plugin().
# Keep public arguments, topics, and capabilities in bywaf.plugin.toml.
@commandlet
def example_library_check(context, cfg, input_events):
    """Place third-party library usage here or in helper modules."""
    del input_events

    # Place third-party library import/use here or in a helper module.
    # If the import can fail, raise a clear ValueError explaining which
    # package the user needs to install.
    context.output(f"checked {cfg.target}")
    yield {"target": cfg.target, "status": "checked"}


def plugin() -> Commandlet:
    return example_library_check
