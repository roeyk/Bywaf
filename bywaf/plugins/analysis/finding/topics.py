"""Topic and source constants shared by finding review/reporting commands.

Used by:
- `finding.Finding` when applying operator review decisions.
- `finding.report.FindingReport` when selecting pipeline or database events.
- `analysis.report` synthesis/rendering code when sharing the normalized
  finding topic contract without depending on report rendering internals.
"""

from __future__ import annotations

DEDUP_FINDING_TOPICS = ("finding.new", "finding.merge_candidate")
REPORT_FINDING_TOPICS = ("finding.candidate", "finding.confirmed", *DEDUP_FINDING_TOPICS)
SOURCE_CHOICES = ("auto", "dedupe", "tools", "all")
