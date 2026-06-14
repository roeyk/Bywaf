"""Command-line interface for architecture and documentation metrics.

Used by:
- `scripts/architecture_metrics.py`: script-compatible wrapper.
- `python -m bywaf.tools.architecture`: module execution path.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .collector import collect_architecture_metrics
from .formatting import format_documentation_impact, format_metrics
from ..documentation.metrics import collect_documentation_impact


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for architecture metrics.

    Called by: `scripts/architecture_metrics.py` and
    `python -m bywaf.tools.architecture`.
    """
    parser = argparse.ArgumentParser(description="Report lightweight Bywaf architecture metrics.")
    parser.add_argument("root", nargs="?", default="bywaf", help="Python package directory to inspect")
    parser.add_argument("--package", default=None, help="Dotted package name; defaults to root directory name")
    parser.add_argument("--tests-root", default=None, help="Test directory for rough module reference counts")
    parser.add_argument("--docs-root", default=None, help="Docs directory for Markdown cohesion/coupling metrics")
    parser.add_argument("--doc-impact", default=None, help="Rank docs related to this changed Markdown file")
    parser.add_argument("--top", type=int, default=12, help="Rows to show in each section")
    parser.add_argument("--churn", action="store_true", help="Include git churn counts from local history")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)
    repo_root = Path(args.root).resolve().parent
    docs_root = Path(args.docs_root) if args.docs_root else None
    if args.doc_impact:
        # Documentation-impact mode is a separate command shape: it ranks docs
        # related to one changed Markdown file instead of collecting source
        # architecture metrics.
        impact = collect_documentation_impact(
            repo_root,
            Path(args.doc_impact),
            docs_root=docs_root,
            top=args.top,
        )
        if args.json:
            print(json.dumps(asdict(impact), indent=2, sort_keys=True))
        else:
            print(format_documentation_impact(impact))
        return 0
    # Normal mode collects source metrics, then includes documentation metrics
    # in the same output object for a full refactor/readability report.
    metrics = collect_architecture_metrics(
        Path(args.root),
        package=args.package,
        tests_root=Path(args.tests_root) if args.tests_root else None,
        docs_root=docs_root,
        include_churn=args.churn,
    )
    if args.json:
        print(json.dumps(asdict(metrics), indent=2, sort_keys=True))
    else:
        print(format_metrics(metrics, top=args.top))
    return 0
