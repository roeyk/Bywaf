#!/usr/bin/env python3
"""Run the Bywaf SQLite contention benchmark from a source checkout."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bywaf.tools.sqlite.contention_benchmark import main


if __name__ == "__main__":
    raise SystemExit(main())
