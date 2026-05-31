"""Process-wrapped Bywaf plugin skeleton.

Use this when a commandlet invokes an external program through
context.process.run() or context.process.stream().
"""

from bywaf.plugin import Commandlet, commandlet

from .parser import parse_tool_output


# LLM Guardrail: bare @commandlet decorates the commandlet function, not plugin().
# Keep public arguments, topics, and capabilities in bywaf.plugin.toml.
@commandlet
def example_wrapped_tool(context, cfg, input_events):
    """Invoke an external tool through the mediated process API."""
    del input_events

    # Place command construction here. Do not use subprocess directly.
    completed = context.process.run(["example-tool", "--json", cfg.target])
    for row in parse_tool_output(completed.stdout):
        yield {"target": cfg.target, **row}


def plugin() -> Commandlet:
    return example_wrapped_tool
