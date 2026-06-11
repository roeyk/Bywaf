"""Plugin checker tests for test skeletons runtime policy."""

from pathlib import Path
import unittest

from scripts.plugin_check import check_plugin, render_text


class TestSkeletonsRuntimePolicyTests(unittest.TestCase):
    def test_plugin_skeletons_validate(self):
        skeleton_root = Path(__file__).resolve().parents[2] / "docs" / "plugin_skeletons"
        failures: list[str] = []
        for plugin_dir in sorted(path for path in skeleton_root.iterdir() if path.is_dir()):
            if not (plugin_dir / "plugin.py").exists():
                continue
            report = check_plugin(plugin_dir, strict_inference=True)
            if not report["ok"]:
                failures.append(render_text(report))

        self.assertEqual([], failures)

    def test_plugin_skeletons_do_not_drift_to_legacy_api(self):
        skeleton_root = Path(__file__).resolve().parents[2] / "docs" / "plugin_skeletons"
        legacy_tokens = (
            "bywaf.findings",
            "bywaf.finding_grouping",
            "bywaf.finding_taxonomy",
            "bywaf.command_parser",
            "bywaf.command_names",
            "bywaf.plugin_process",
            "BaseCommandlet",
            "info =",
            "def exploit(",
        )
        failures: list[str] = []
        for path in skeleton_root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for token in legacy_tokens:
                if token in text:
                    failures.append(f"{path}: legacy token {token!r}")
            if path.name == "plugin.py":
                plugin_factory = text.split("def plugin", 1)[1] if "def plugin" in text else ""
                if "@commandlet" in plugin_factory:
                    failures.append(f"{path}: @commandlet must not decorate plugin()")

        self.assertEqual([], failures)

    def test_vulnerability_skeletons_keep_split_files_and_finding_helpers(self):
        skeleton_root = Path(__file__).resolve().parents[2] / "docs" / "plugin_skeletons"
        required = {"plugin.py", "command.py", "detect.py", "findings.py", "models.py", "bywaf.plugin.toml"}
        failures: list[str] = []
        for plugin_dir in sorted(path for path in skeleton_root.iterdir() if path.is_dir() and "vulnerability" in path.name):
            present = {path.name for path in plugin_dir.iterdir() if path.is_file()}
            missing = sorted(required - present)
            if missing:
                failures.append(f"{plugin_dir}: missing {', '.join(missing)}")
            findings = plugin_dir.joinpath("findings.py").read_text(encoding="utf-8")
            if "from bywaf.finding import candidate_payload" not in findings:
                failures.append(f"{plugin_dir}/findings.py: missing current candidate_payload import")
            if "candidate_payload(" not in findings:
                failures.append(f"{plugin_dir}/findings.py: missing candidate_payload usage")
            if "confirmed_payload(" in findings and "from bywaf.finding import candidate_payload, confirmed_payload" not in findings:
                failures.append(f"{plugin_dir}/findings.py: missing confirmed_payload import")

        self.assertEqual([], failures)

    def test_runtime_code_uses_context_for_artifact_store_access(self):
        root = Path(__file__).resolve().parents[2]
        allowed = {
            root / "bywaf" / "artifact_store.py",
            root / "bywaf" / "artifacts.py",
            root / "bywaf" / "plugin" / "context.py",
            root / "bywaf" / "plugin" / "context" / "__init__.py",
            root / "bywaf" / "plugin" / "services" / "__init__.py",
            root / "bywaf" / "plugin" / "services" / "artifacts.py",
        }
        offenders: list[str] = []
        for path in (root / "bywaf").rglob("*.py"):
            if path in allowed:
                continue
            if "artifact_store_for_event_store" in path.read_text(encoding="utf-8"):
                offenders.append(str(path.relative_to(root)))

        self.assertEqual([], offenders)

    def test_runtime_artifact_store_access_declares_access_intent(self):
        root = Path(__file__).resolve().parents[2]
        completion_exception = root / "bywaf" / "plugins" / "runtime" / "artifact" / "completion.py"
        offenders: list[str] = []
        for path in (root / "bywaf" / "plugins").rglob("*.py"):
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if "context.artifact_store(" not in line:
                    continue
                if "read_access=" in line or "write_access=" in line:
                    continue
                if path == completion_exception:
                    continue
                offenders.append(f"{path.relative_to(root)}:{lineno}")

        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
