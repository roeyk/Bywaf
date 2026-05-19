#!/usr/bin/env python3
"""Run a user-facing Bywaf script as a regression flow.

Flow files are ordinary `.bywaf` scripts with optional assertion comments:

    # EXPECT: text that must appear in console output
    # EXPECT-EVENT: topic that must exist in the event DB

The runner substitutes `{tmp}`, `{db}`, and `{fixture}` before execution so
scripts can stay readable without hard-coding machine-local paths.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from bywaf.app import ShellState, make_runner, run_script


@dataclass(frozen=True, slots=True)
class FlowAssertions:
    """Expected output fragments and event topics for one flow."""

    output: tuple[str, ...]
    events: tuple[str, ...]


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for script-flow regression tests."""
    parser = argparse.ArgumentParser(prog="run_user_flow.py")
    parser.add_argument("script", type=Path)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--tmp", type=Path)
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory() as temp_name:
        tmp = args.tmp or Path(temp_name)
        tmp.mkdir(parents=True, exist_ok=True)
        database = args.database or tmp / "bywaf.sqlite3"
        fixture = tmp / "evidence.txt"
        fixture.write_text("user-flow evidence\n", encoding="utf-8")
        flow_script = materialize_flow(args.script, tmp=tmp, database=database, fixture=fixture)
        assertions = read_assertions(args.script)
        output = run_flow(flow_script, database)
        try:
            assert_flow(output, database, assertions)
        except AssertionError as exc:
            print(output)
            print(f"flow assertion failed: {exc}", file=sys.stderr)
            return 1
    return 0


def materialize_flow(source: Path, *, tmp: Path, database: Path, fixture: Path) -> Path:
    """Write a substituted copy of a flow script to a temporary path."""
    text = source.read_text(encoding="utf-8")
    text = text.replace("{tmp}", str(tmp))
    text = text.replace("{db}", str(database))
    text = text.replace("{fixture}", str(fixture))
    path = tmp / source.name
    path.write_text(text, encoding="utf-8")
    return path


def read_assertions(path: Path) -> FlowAssertions:
    """Parse assertion comments from a flow script."""
    output: list[str] = []
    events: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("# EXPECT:"):
            output.append(line.split(":", 1)[1].strip())
        elif line.startswith("# EXPECT-EVENT:"):
            events.append(line.split(":", 1)[1].strip())
    return FlowAssertions(tuple(output), tuple(events))


def run_flow(script: Path, database: Path) -> str:
    """Execute one script through Bywaf's normal script loader."""
    runner = make_runner(database)
    state = ShellState(framework_request_after_id=runner.events.latest_event_id())
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        run_script(runner, script, state)
    return output.getvalue()


def assert_flow(output: str, database: Path, assertions: FlowAssertions) -> None:
    """Check console and event assertions for a completed flow."""
    for expected in assertions.output:
        if expected not in output:
            raise AssertionError(f"missing output fragment: {expected!r}")
    if assertions.events:
        from bywaf.db import EventStore

        db = EventStore(database)
        topics = set(db.topics())
        for topic in assertions.events:
            if topic not in topics:
                raise AssertionError(f"missing event topic: {topic!r}")


if __name__ == "__main__":
    os.environ.setdefault("BYWAF_INPUT_READER", "readline")
    raise SystemExit(main())
