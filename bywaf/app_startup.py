"""Startup project, database, and setup helpers for the top-level CLI.

Used by:
- bywaf.app.main(): resolves project/database selection and setup before
  constructing the runner.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .operator_state import load_ad_hoc_active_database
from .projects import ProjectPaths, create_project, require_project
from .setup import first_run_notice_needed, print_first_run_notice, run_setup


def startup_database_path(project: ProjectPaths | None, database: str | Path, *, explicit_database: bool) -> Path:
    """Return the DB path startup should open for this invocation.

    Called by: `bywaf.app.main()` after project selection and before runner
    construction.
    """
    if project is not None:
        return project.database
    if explicit_database:
        return Path(database)
    return load_ad_hoc_active_database() or Path(database)


def handle_setup_startup(args: argparse.Namespace) -> int | None:
    """Handle explicit setup or the optional interactive first-run notice.

    Called by: `bywaf.app.main()` before project/database startup.
    """
    if args.setup:
        try:
            run_setup(output=not args.quiet, include_plugin_signing_keys=args.setup_plugin_signing_keys)
        except (KeyboardInterrupt, EOFError):
            print("setup cancelled")
            return 1
        except (RuntimeError, ValueError) as exc:
            print(f"error: {exc}")
            return 1
        return 0
    if args.subcommand in ("repl", None) and first_run_notice_needed(quiet=args.quiet):
        print_first_run_notice()
    return None


def startup_project(name: str | None, *, create: bool) -> ProjectPaths | None:
    """Resolve or create a startup project selected from the OS command line.

    Called by: `bywaf.app.main()` after setup handling.
    """
    if name is None:
        return None
    return create_project(name) if create else require_project(name)
