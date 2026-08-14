import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "operations" / "check-module-quality.py"
SPEC = importlib.util.spec_from_file_location("module_quality_gate", SCRIPT)
quality = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(quality)


def policy(**updates):
    value = {
        "schema": quality.POLICY_SCHEMA,
        "module_target_lines": 10,
        "new_module_max_lines": 20,
        "absolute_new_file_max_lines": 30,
        "function_target_lines": 5,
        "new_function_max_lines": 10,
        "complexity_target": 3,
        "new_complexity_max": 5,
        "include": ["src/*.py"],
        "exclude": [],
        "python_import_roots": ["src"],
        "forbidden_dependencies": [],
    }
    value.update(updates)
    return quality.validate_policy(value)


def baseline(files=None, functions=None):
    return quality.validate_baseline(
        {
            "schema": quality.BASELINE_SCHEMA,
            "source_release": "test",
            "files": files or {},
            "functions": functions or {},
        }
    )


class ModuleQualityGateTests(unittest.TestCase):
    def test_metric_issues_preserves_classification_and_order(self) -> None:
        configured = policy()
        metrics = {
            "files": {
                "file-failure": {"lines": 21},
                "file-warning": {"lines": 20},
                "file-target": {"lines": 10},
            },
            "functions": {
                "function-both-failures": {"lines": 11, "complexity": 6},
                "function-both-warnings": {"lines": 10, "complexity": 5},
                "function-target": {"lines": 5, "complexity": 3},
            },
        }

        failures, warnings = quality.metric_issues(
            metrics,
            configured,
            baseline(),
        )

        self.assertEqual(
            failures,
            [
                quality.issue("module_lines", "file-failure", 21, 20),
                quality.issue(
                    "function_lines",
                    "function-both-failures",
                    11,
                    10,
                ),
                quality.issue(
                    "function_complexity",
                    "function-both-failures",
                    6,
                    5,
                ),
            ],
        )
        self.assertEqual(
            warnings,
            [
                quality.issue("module_lines", "file-warning", 20, 10),
                quality.issue(
                    "function_lines",
                    "function-both-warnings",
                    10,
                    5,
                ),
                quality.issue(
                    "function_complexity",
                    "function-both-warnings",
                    5,
                    3,
                ),
            ],
        )
        second_failures, second_warnings = quality.metric_issues(
            metrics,
            configured,
            baseline(),
        )
        self.assertIsNot(failures, second_failures)
        self.assertIsNot(warnings, second_warnings)
        self.assertEqual((failures, warnings), (second_failures, second_warnings))

    def test_metric_issues_preserves_policy_and_issue_call_order(self) -> None:
        configured = policy()
        metrics = {
            "files": {
                "file-failure": {"lines": 21},
                "file-warning": {"lines": 11},
            },
            "functions": {
                "function-warning": {"lines": 6, "complexity": 4},
            },
        }
        calls = []
        sentinels = []

        def traced_positive_integer(value, name):
            calls.append(("policy", name))
            return quality_positive_integer(value, name)

        def traced_issue(kind, name, measured, allowed):
            calls.append(("issue", kind, name, measured, allowed))
            token = object()
            sentinels.append(token)
            return token

        quality_positive_integer = quality.positive_integer
        with mock.patch.object(
            quality,
            "positive_integer",
            side_effect=traced_positive_integer,
        ), mock.patch.object(quality, "issue", side_effect=traced_issue):
            failures, warnings = quality.metric_issues(
                metrics,
                configured,
                baseline(),
            )

        self.assertEqual(
            calls,
            [
                ("policy", "module_target_lines"),
                ("policy", "new_module_max_lines"),
                ("policy", "function_target_lines"),
                ("policy", "new_function_max_lines"),
                ("policy", "complexity_target"),
                ("policy", "new_complexity_max"),
                ("issue", "module_lines", "file-failure", 21, 20),
                ("issue", "module_lines", "file-warning", 11, 10),
                ("issue", "function_lines", "function-warning", 6, 5),
                (
                    "issue",
                    "function_complexity",
                    "function-warning",
                    4,
                    3,
                ),
            ],
        )
        self.assertEqual(failures, [sentinels[0]])
        self.assertEqual(warnings, sentinels[1:])
        self.assertIs(failures[0], sentinels[0])
        self.assertIs(warnings[0], sentinels[1])

    def test_metric_issues_admits_only_dictionary_baseline_debt(self) -> None:
        class DebtDict(dict):
            pass

        metrics = {
            "files": {
                "dict-subclass": {"lines": 21},
                "mapping-only": {"lines": 21},
            },
            "functions": {
                "dict-subclass": {"lines": 11, "complexity": 6},
                "mapping-only": {"lines": 11, "complexity": 6},
            },
        }
        configured_baseline = baseline(
            files={
                "dict-subclass": DebtDict(max_lines=21),
                "mapping-only": mock.MagicMock(
                    spec=["get"],
                    **{"get.return_value": 21},
                ),
            },
            functions={
                "dict-subclass": DebtDict(
                    max_lines=11,
                    max_complexity=6,
                ),
                "mapping-only": mock.MagicMock(
                    spec=["get"],
                    **{"get.return_value": 99},
                ),
            },
        )

        failures, warnings = quality.metric_issues(
            metrics,
            policy(),
            configured_baseline,
        )

        self.assertEqual(
            [(item["kind"], item["name"]) for item in failures],
            [
                ("module_lines", "mapping-only"),
                ("function_lines", "mapping-only"),
                ("function_complexity", "mapping-only"),
            ],
        )
        self.assertEqual(
            [(item["kind"], item["name"]) for item in warnings],
            [
                ("module_lines", "dict-subclass"),
                ("function_lines", "dict-subclass"),
                ("function_complexity", "dict-subclass"),
            ],
        )
        configured_baseline["files"]["mapping-only"].get.assert_not_called()
        configured_baseline["functions"]["mapping-only"].get.assert_not_called()

    def test_metric_issues_stops_at_policy_or_issue_failure(self) -> None:
        metrics = {
            "files": {
                "first": {"lines": 21},
                "second": {"lines": 22},
            },
            "functions": {},
        }
        configured = policy()
        calls = []

        def fail_policy(value, name):
            calls.append(("policy", name))
            if name == "function_target_lines":
                raise RuntimeError("policy-stop")
            return value[name]

        with mock.patch.object(
            quality,
            "positive_integer",
            side_effect=fail_policy,
        ):
            with self.assertRaisesRegex(RuntimeError, "policy-stop"):
                quality.metric_issues(metrics, configured, baseline())
        self.assertEqual(
            calls,
            [
                ("policy", "module_target_lines"),
                ("policy", "new_module_max_lines"),
                ("policy", "function_target_lines"),
            ],
        )

        calls.clear()

        def fail_issue(kind, name, measured, allowed):
            calls.append((kind, name, measured, allowed))
            raise LookupError("issue-stop")

        with mock.patch.object(quality, "issue", side_effect=fail_issue):
            with self.assertRaisesRegex(LookupError, "issue-stop"):
                quality.metric_issues(metrics, configured, baseline())
        self.assertEqual(calls, [("module_lines", "first", 21, 20)])

    def test_repository_baseline_passes(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(ROOT)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_repository_baseline_contains_only_current_debt(self) -> None:
        policy_path = ROOT / "operations/quality/module-quality-policy.json"
        baseline_path = ROOT / "operations/quality/module-quality-baseline.json"
        configured = quality.validate_policy(quality.read_object(policy_path))
        checked_in = quality.validate_baseline(quality.read_object(baseline_path))
        names = quality.selected_sources(ROOT, configured)
        metrics = quality.source_metrics(ROOT, names)
        current = quality.candidate_baseline(
            metrics,
            configured,
            quality.git_release(ROOT),
        )
        self.assertEqual(checked_in["files"], current["files"])
        self.assertEqual(checked_in["functions"], current["functions"])

    def test_new_oversized_module_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src/large.py").write_text("value = 1\n" * 21)
            report = quality.evaluate(root, policy(), baseline())
        self.assertFalse(report["ok"])
        self.assertIn("module_lines", {item["kind"] for item in report["failures"]})

    def test_grandfathered_module_cannot_grow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src/legacy.py").write_text("value = 1\n" * 26)
            report = quality.evaluate(
                root,
                policy(),
                baseline(files={"src/legacy.py": {"max_lines": 25}}),
            )
        self.assertFalse(report["ok"])
        failure = next(item for item in report["failures"] if item["kind"] == "module_lines")
        self.assertEqual(failure["allowed"], 25)

    def test_new_large_or_complex_function_fails(self) -> None:
        source = "def risky(a, b, c, d, e, f):\n"
        source += "    if a and b and c and d and e and f:\n"
        source += "        return 1\n"
        source += "    return 0\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src/risky.py").write_text(source)
            report = quality.evaluate(root, policy(), baseline())
        self.assertFalse(report["ok"])
        self.assertIn(
            "function_complexity",
            {item["kind"] for item in report["failures"]},
        )

    def test_new_long_function_fails(self) -> None:
        source = "def too_long():\n" + "    value = 1\n" * 10
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src/long.py").write_text(source)
            report = quality.evaluate(root, policy(), baseline())
        self.assertFalse(report["ok"])
        self.assertIn("function_lines", {item["kind"] for item in report["failures"]})

    def test_import_cycle_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src/a.py").write_text("import b\n")
            (root / "src/b.py").write_text("import a\n")
            report = quality.evaluate(root, policy(), baseline())
        self.assertFalse(report["ok"])
        self.assertIn("import_cycle", {item["kind"] for item in report["failures"]})

    def test_relative_package_import_cycle_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src/pkg").mkdir(parents=True)
            (root / "src/pkg/__init__.py").write_text("")
            (root / "src/pkg/a.py").write_text("from . import b\n")
            (root / "src/pkg/b.py").write_text("from .a import value\nvalue = 1\n")
            configured = policy(
                include=["src/**/*.py"],
                python_import_roots=["src"],
            )
            report = quality.evaluate(root, configured, baseline())
        self.assertFalse(report["ok"])
        self.assertIn("import_cycle", {item["kind"] for item in report["failures"]})

    def test_forbidden_dependency_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src/domain.py").write_text("import adapter\n")
            (root / "src/adapter.py").write_text("value = 1\n")
            configured = policy(
                forbidden_dependencies=[
                    {"from": "src/domain.py", "to": "src/adapter.py"}
                ]
            )
            report = quality.evaluate(root, configured, baseline())
        self.assertFalse(report["ok"])
        self.assertIn(
            "forbidden_dependency",
            {item["kind"] for item in report["failures"]},
        )

    def test_candidate_baseline_records_only_enforced_debt(self) -> None:
        metrics = {
            "files": {"src/a.py": {"lines": 21}, "src/b.py": {"lines": 10}},
            "functions": {
                "src/a.py::large": {"lines": 11, "complexity": 2},
                "src/b.py::complex": {"lines": 3, "complexity": 6},
            },
        }
        candidate = quality.candidate_baseline(metrics, policy(), "abc")
        self.assertEqual(candidate["files"], {"src/a.py": {"max_lines": 21}})
        self.assertEqual(
            candidate["functions"],
            {
                "src/a.py::large": {"max_lines": 11},
                "src/b.py::complex": {"max_complexity": 6},
            },
        )

    def test_quality_policy_is_stricter_for_new_code_than_absolute_ceiling(self) -> None:
        configured = json.loads(
            (ROOT / "operations/quality/module-quality-policy.json").read_text()
        )
        self.assertLessEqual(
            configured["new_module_max_lines"],
            configured["absolute_new_file_max_lines"],
        )
        self.assertEqual(configured["new_module_max_lines"], 800)
        self.assertEqual(configured["new_function_max_lines"], 100)
        self.assertEqual(configured["new_complexity_max"], 15)


if __name__ == "__main__":
    unittest.main()
