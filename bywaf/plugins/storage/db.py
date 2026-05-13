"""Active database management commandlet."""

from __future__ import annotations

import argparse
from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import ArgumentSpec, CommandContext, CommandSpec, Commandlet, CompletionSpec


class Db:
    """Expose safe operational controls for the active SQLite database."""

    spec = CommandSpec(
        name="db",
        description="Manage the active Bywaf SQLite database.",
        usage="db <status|path|checkpoint|vacuum>",
        examples=("db status", "db checkpoint", "db vacuum"),
        arguments=(
            ArgumentSpec(
                "action",
                "database operation",
                completion=CompletionSpec("choice", ("checkpoint", "path", "status", "vacuum")),
            ),
        ),
    )

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse the database action and run it against the active store."""
        parser = argparse.ArgumentParser(prog=self.spec.name)
        parser.add_argument("action", choices=("checkpoint", "path", "status", "vacuum"))
        parsed = parser.parse_args(args)
        if context.db is None:
            raise ValueError("db command requires an active database")
        match parsed.action:
            case "checkpoint":
                context.db.checkpoint()
                print("checkpoint complete")
            case "path":
                print(context.db.path)
            case "status":
                print_database_status(context)
            case "vacuum":
                context.db.vacuum()
                print("vacuum complete")
        return ()


def print_database_status(context: CommandContext) -> None:
    """Print a concise status summary for the active database."""
    if context.db is None:
        raise ValueError("db command requires an active database")
    counts = context.db.table_counts()
    mode = "encrypted" if context.db.encrypted else "plaintext"
    print(f"path={context.db.path}")
    print(f"mode={mode}")
    print(f"events={counts['events']}")
    print(f"jobs={counts['jobs']}")


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return Db()
