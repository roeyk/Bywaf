#!/usr/bin/env python3
"""Manual portscanner workflow smoke runner.

Runs the operator-facing scan and filter sequence that is useful during manual
testing: fresh database, DNS-backed port scan, event filtering, variable
expansion in filters, and runtime-scope filtering.

Used by:
- local/manual validation: reproduce a compact workflow without typing each
  REPL command by hand.
- maintainers: confirm real nmap/libnmap behavior outside mocked unit tests."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from bywaf.app import dispatch_repl_line, make_runner, new_shell_state


def main() -> int:
    """Run the manual smoke workflow."""
    parser = argparse.ArgumentParser(prog="manual_portscanner_flow.py")
    parser.add_argument("--target", default="google.com", help="DNS name or host to scan")
    parser.add_argument("--ports", default="80,443", help="comma-separated ports to scan")
    parser.add_argument("--arguments", default="-Pn -sT -4", help="nmap arguments")
    parser.add_argument("--database", type=Path, help="database path to create/use")
    args = parser.parse_args()

    database = args.database or default_database_path()
    database.parent.mkdir(parents=True, exist_ok=True)
    runner = make_runner(database)
    state = new_shell_state(runner)

    print(f"database={database}")
    run_line(runner, state, f'network/portscanner host={args.target} ports={args.ports} arguments="{args.arguments}"')
    run_line(runner, state, "event port.open")
    run_line(runner, state, "event name.resolved")

    host = first_open_port_host(runner)
    if host is None:
        print("no port.open events found; skipping host-scoped filter checks")
        return 2

    run_line(runner, state, f"set A={host} # testing filtering")
    run_line(runner, state, "set A")
    run_line(runner, state, "event port.open host=$A")
    run_line(runner, state, "jobs host=$A; steps host=$A; pipelines host=$A")
    return 0


def default_database_path() -> Path:
    """Return a timestamped manual-test database path under `.bywaf/db`."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path(".bywaf") / "db" / f"manual-portscanner-{stamp}.sqlite3"


def run_line(runner, state, line: str) -> None:
    """Print and dispatch one REPL-style command line."""
    print(f"\nbywaf> {line}")
    dispatch_repl_line(runner, line, state)


def first_open_port_host(runner) -> str | None:
    """Return the first host from persisted `port.open` events."""
    for event in runner.db.events_for_topic("port.open", limit=1000):
        host = event.payload.get("host")
        if host:
            return str(host)
    return None


if __name__ == "__main__":
    raise SystemExit(main())
