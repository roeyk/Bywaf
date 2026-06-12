"""Tests for architecture and documentation metric collection.

Used by:
- maintainers: validate the metrics that guide refactoring and documentation
  pressure reviews.
- CI: keep the synthetic fixture behavior stable as the metric collector grows.
Coverage focus: architecture metrics regression behavior.
"""

from pathlib import Path

from bywaf.tools.architecture import (
    collect_architecture_metrics,
    format_documentation_impact,
    format_metrics,
)
from bywaf.tools.documentation_metrics import collect_documentation_impact, collect_documentation_metrics


def write(path: Path, text: str) -> None:
    """Create a fixture file for an in-test package or docs tree."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_architecture_metrics_counts_internal_imports_and_cycles(tmp_path: Path) -> None:
    root = tmp_path / "pkg"
    tests_root = tmp_path / "tests"
    # Build a tiny package with an import cycle, one branch, one external
    # import, one sensitive-looking token, and one test reference.
    write(root / "__init__.py", "")
    write(root / "a.py", "from . import b\n\ndef branch(x):\n    if x:\n        return 1\n    return 0\n")
    write(root / "b.py", "from pkg import c\n")
    write(root / "c.py", "import pkg.a\n")
    write(root / "external.py", "import json\nPASSWORD = 'x'\n")
    write(tests_root / "test_a.py", "from pkg.a import branch\n")

    metrics = collect_architecture_metrics(root, package="pkg", tests_root=tests_root)
    by_name = {module.name: module for module in metrics.modules}

    # The assertions below pin each signal independently so regressions say
    # which part of the collector changed.
    assert metrics.module_count == 5
    assert by_name["pkg.a"].imports == ("pkg.b",)
    assert by_name["pkg.b"].imports == ("pkg.c",)
    assert by_name["pkg.c"].imports == ("pkg.a",)
    assert by_name["pkg.a"].function_count == 1
    assert by_name["pkg.a"].max_function_complexity > 1
    assert by_name["pkg.a"].documentation_pressure > 0
    assert by_name["pkg.a"].test_refs == 1
    assert by_name["pkg.external"].security_hits == 1
    assert any({"pkg.a", "pkg.b", "pkg.c"} == set(cycle) for cycle in metrics.cycles)


def test_architecture_metrics_ignores_type_checking_imports(tmp_path: Path) -> None:
    root = tmp_path / "pkg"
    write(root / "__init__.py", "")
    # TYPE_CHECKING imports are documentation/type hints, not runtime edges,
    # so they should not create coupling or cycles.
    write(
        root / "a.py",
        "from typing import TYPE_CHECKING\n\n"
        "if TYPE_CHECKING:\n"
        "    from . import b\n\n"
        "VALUE = 1\n",
    )
    write(
        root / "b.py",
        "import typing\n\n"
        "if typing.TYPE_CHECKING:\n"
        "    import pkg.a\n\n"
        "VALUE = 2\n",
    )

    metrics = collect_architecture_metrics(root, package="pkg")
    by_name = {module.name: module for module in metrics.modules}

    assert by_name["pkg.a"].imports == ()
    assert by_name["pkg.b"].imports == ()
    assert metrics.cycles == ()


def test_architecture_metrics_text_report_names_pressure_points(tmp_path: Path) -> None:
    root = tmp_path / "pkg"
    write(root / "__init__.py", "")
    write(root / "hub.py", "import pkg.leaf\n")
    write(root / "leaf.py", "VALUE = 1\n")

    report = format_metrics(collect_architecture_metrics(root, package="pkg"), top=2)

    assert "Architecture metrics for pkg" in report
    assert "Highest fan-out" in report
    assert "Highest module complexity" in report
    assert "Highest documentation pressure" in report
    assert "High hub score with low test references" in report
    assert "pkg.hub" in report


def test_architecture_metrics_reports_documentation_pressure(tmp_path: Path) -> None:
    root = tmp_path / "pkg"
    docs = tmp_path / "docs"
    write(root / "__init__.py", "")
    write(root / "a.py", "VALUE = 1\n")
    # This markdown fixture intentionally includes stale run wording, a
    # duplicate heading, an audience term, and a broken link.
    write(
        docs / "README.md",
        "# Docs\n\n"
        "For plugin author and operator paths, see [Guide](guide.md).\n\n"
        "## Run\n\n"
        "Old run= wording.\n\n"
        "## Run\n\n"
        "Duplicate heading.\n",
    )
    write(docs / "guide.md", "# Guide\n\nSee [Missing](missing.md).\n")

    metrics = collect_architecture_metrics(root, package="pkg", docs_root=docs)
    report = format_metrics(metrics, top=3)
    assert metrics.docs is not None
    docs_by_path = {document.path: document for document in metrics.docs.documents}

    assert "Documentation metrics" in report
    assert "Highest doc link coupling" in report
    assert docs_by_path["docs/README.md"].duplicate_headings == 1
    assert docs_by_path["docs/README.md"].stale_terms >= 1
    assert metrics.docs.broken_links == ("docs/guide.md -> missing.md",)


def test_documentation_metrics_can_run_without_python_package(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    write(docs / "a.md", "# A\n\nSee [B](b.md).\n")
    write(docs / "b.md", "# B\n")

    metrics = collect_documentation_metrics(tmp_path, docs_root=docs)
    by_path = {document.path: document for document in metrics.documents}

    assert metrics.document_count == 2
    assert metrics.link_count == 1
    assert by_path["docs/a.md"].outbound_links == 1
    assert by_path["docs/b.md"].inbound_links == 1


def test_documentation_impact_ranks_linked_and_related_docs(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    # The two finding/reporting pages are bidirectionally linked and share
    # domain terms; plugins.md is a distractor with unrelated vocabulary.
    write(
        docs / "reporting.md",
        "# Reporting\n\n"
        "See [Finding Model](finding.md).\n\n"
        "## Review State\n\n"
        "Finding review accepts deferred rejected finding rows.\n",
    )
    write(
        docs / "finding.md",
        "# Finding Model\n\n"
        "See [Reporting](reporting.md).\n\n"
        "Finding review grouping target_scope finding rows.\n",
    )
    write(docs / "plugins.md", "# Plugins\n\nCommandlet manifest skeleton plugin.\n")

    impact = collect_documentation_impact(tmp_path, docs / "reporting.md", docs_root=docs, top=2)
    rendered = format_documentation_impact(impact)

    assert impact.source == "docs/reporting.md"
    assert impact.related[0].path == "docs/finding.md"
    assert any("source links to it" in reason for reason in impact.related[0].reasons)
    assert "Documentation impact for docs/reporting.md" in rendered
