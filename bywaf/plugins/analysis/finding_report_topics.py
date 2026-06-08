"""Topic and source constants for finding reports.

Used by:
- `finding_report.FindingReport` when selecting pipeline or database events.
- `finding` and `report` commandlets when sharing the normalized finding topic
  contract without depending on finding report rendering internals.
"""

from __future__ import annotations

DEDUP_FINDING_TOPICS = ("finding.new", "finding.merge_candidate")
REPORT_FINDING_TOPICS = ("finding.candidate", "finding.confirmed", *DEDUP_FINDING_TOPICS)
SOURCE_CHOICES = ("auto", "dedupe", "tools", "all")
