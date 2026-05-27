from pathlib import Path

from bywaf.tools.architecture_metrics import collect_architecture_metrics, format_metrics


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_architecture_metrics_counts_internal_imports_and_cycles(tmp_path: Path) -> None:
    root = tmp_path / "pkg"
    tests_root = tmp_path / "tests"
    write(root / "__init__.py", "")
    write(root / "a.py", "from . import b\n\ndef branch(x):\n    if x:\n        return 1\n    return 0\n")
    write(root / "b.py", "from pkg import c\n")
    write(root / "c.py", "import pkg.a\n")
    write(root / "external.py", "import json\nPASSWORD = 'x'\n")
    write(tests_root / "test_a.py", "from pkg.a import branch\n")

    metrics = collect_architecture_metrics(root, package="pkg", tests_root=tests_root)
    by_name = {module.name: module for module in metrics.modules}

    assert metrics.module_count == 5
    assert by_name["pkg.a"].imports == ("pkg.b",)
    assert by_name["pkg.b"].imports == ("pkg.c",)
    assert by_name["pkg.c"].imports == ("pkg.a",)
    assert by_name["pkg.a"].function_count == 1
    assert by_name["pkg.a"].max_function_complexity > 1
    assert by_name["pkg.a"].test_refs == 1
    assert by_name["pkg.external"].security_hits == 1
    assert any({"pkg.a", "pkg.b", "pkg.c"} == set(cycle) for cycle in metrics.cycles)


def test_architecture_metrics_text_report_names_pressure_points(tmp_path: Path) -> None:
    root = tmp_path / "pkg"
    write(root / "__init__.py", "")
    write(root / "hub.py", "import pkg.leaf\n")
    write(root / "leaf.py", "VALUE = 1\n")

    report = format_metrics(collect_architecture_metrics(root, package="pkg"), top=2)

    assert "Architecture metrics for pkg" in report
    assert "Highest fan-out" in report
    assert "Highest module complexity" in report
    assert "High hub score with low test references" in report
    assert "pkg.hub" in report
