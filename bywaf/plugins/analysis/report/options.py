"""Shared report/finding selector constants.

Used by:
- `analysis.report`: command parsing and completion for report views.
- `analysis.finding`: finding-review parsing that must match report row
  grouping and review-status vocabulary without importing the report commandlet.
"""

REPORT_ANALYZE_CHOICES = ("off", "passive")
REPORT_OPTION_KEYS = {"analyze", "cve", "job", "pipeline", "step", "limit", "name", "note", "page", "sort", "status"}
REPORT_STATUS_CHOICES = ("all", "accepted", "confirmed", "deferred", "open", "rejected", "unreviewed")
REPORT_SORT_CHOICES = ("finding", "host")
