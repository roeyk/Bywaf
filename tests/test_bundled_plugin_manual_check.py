from pathlib import Path

from bywaf.tools.bundled_plugin_manual_check import check_manual


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_manifest(path: Path, commandlets: tuple[str, ...]) -> None:
    rows = ["[plugin]", 'version = "0.1.0"', ""]
    for commandlet in commandlets:
        rows.extend(("[[commandlets]]", f'name = "{commandlet}"', ""))
    write(path, "\n".join(rows))


def manual_text(*, analysis_count: int = 1, commandlet_count: int = 2) -> str:
    return f"""# Bundled Plugin Manual

## Table Of Contents

<div class="plugin-toc">
<div class="toc-header"><span class="toc-count">Plugins (Commandlets)</span><span class="toc-name">Name</span></div>
<details class="plugin-toc-family">
<summary id="toc-analysis"><span class="toc-count">{analysis_count}</span><span class="toc-arrow" aria-hidden="true">▸</span><span class="toc-name">Analysis</span></summary>
<div class="toc-entry"><span class="toc-count toc-child-count">{commandlet_count}</span><span class="toc-name"><a href="#analysisexample">analysis.example</a></span></div>
</details>
</div>

## Analysis

### Analysis Plugin TOC

- [analysis.example](#analysisexample)

<a id="analysisexample"></a>

### `analysis.example`

#### Commandlets: `alpha`, `beta`
"""


def test_bundled_plugin_manual_check_accepts_matching_manual(tmp_path: Path) -> None:
    plugin_root = tmp_path / "bywaf" / "plugins"
    write_manifest(plugin_root / "analysis" / "example.plugin.toml", ("alpha", "beta"))
    manual = tmp_path / "docs" / "BUNDLED_PLUGIN_MANUAL.md"
    write(manual, manual_text())

    assert check_manual(manual, plugin_root) == []


def test_bundled_plugin_manual_check_reports_drift(tmp_path: Path) -> None:
    plugin_root = tmp_path / "bywaf" / "plugins"
    write_manifest(plugin_root / "analysis" / "example.plugin.toml", ("alpha", "beta"))
    manual = tmp_path / "docs" / "BUNDLED_PLUGIN_MANUAL.md"
    write(manual, manual_text(analysis_count=2, commandlet_count=1).replace("`beta`", "`gamma`"))

    errors = check_manual(manual, plugin_root)

    assert any("top TOC family counts differ" in error for error in errors)
    assert any("analysis.example top TOC commandlet count is 1" in error for error in errors)
    assert any("analysis.example commandlets differ" in error for error in errors)
