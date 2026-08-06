import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


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
    def test_repository_baseline_passes(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(ROOT)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

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
