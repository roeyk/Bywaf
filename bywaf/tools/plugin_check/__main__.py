"""Module entrypoint for `python -m bywaf.tools.plugin_check`.

Used by: documentation and maintainers who prefer module execution over the
`scripts/plugin_check.py` wrapper.
"""

from __future__ import annotations

from scripts.plugin_check import main


raise SystemExit(main())
