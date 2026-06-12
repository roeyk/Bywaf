"""SQLite benchmark tool implementations.

Used by:
- `scripts/sqlite_contention_benchmark.py` and
  `scripts/sqlite_query_benchmark.py`: source-checkout command wrappers.
- `docs/PERFORMANCE.md` and `docs/TOOLS.md`: documented performance
  measurement flows for maintainers.

This package keeps SQLite-specific benchmark implementations together while
leaving the public script names stable for operators and maintainers.
"""
