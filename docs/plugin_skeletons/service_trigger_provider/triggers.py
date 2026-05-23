"""Provider-owned trigger rules for a service plugin."""

from bywaf.plugin import TriggerSpec


def triggers() -> tuple[TriggerSpec, ...]:
    """Return trigger rules owned by this provider.

    Users do not define these triggers directly. The plugin exposes them via
    this function and declares matching [[triggers]] rows in bywaf.plugin.toml.
    """
    return (
        TriggerSpec(
            name="start-example-service",
            description="Start example service after network capability use.",
            topic="plugin.capability.used",
            capability="network.connect",
            action_command="example_service --session-service",
            action_mode="service",
            active_job=True,
            exclude_commandlets=("example_service",),
            suppress_self_trigger=True,
        ),
    )
