"""Module entrypoint for `python -m bywaf.tools.architecture`.

Used by: maintainers who run architecture metrics as a module instead of via
`scripts/architecture_metrics.py`.
"""

from __future__ import annotations

from . import main


raise SystemExit(main())
