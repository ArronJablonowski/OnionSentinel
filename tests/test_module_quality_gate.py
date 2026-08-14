import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from contextlib import redirect_stderr, redirect_stdout


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
    def main_args(self, **updates):
        values = {
            "root": Path("/quality-root"),
            "policy": Path("/quality-policy.json"),
            "baseline": Path("/quality-baseline.json"),
            "json": False,
            "print_current_baseline": False,
            "update_baseline": False,
        }
        values.update(updates)
        return SimpleNamespace(**values)

    def invoke_main(self, args, report):
        calls = []
        configured_policy = {"configured": "policy"}
        configured_baseline = {"configured": "baseline"}
        metrics = {"files": {"a.py": {}}, "functions": {"a.py::f": {}}}
        candidate = {"schema": "candidate", "files": {}, "functions": {}}

        def read_object(path):
            calls.append(("read_object", str(path)))
            return {"path": str(path)}

        def validate_policy(value):
            calls.append(("validate_policy", value["path"]))
            return configured_policy

        def selected_sources(root, policy_value):
            calls.append(("selected_sources", str(root), policy_value))
            return ["a.py"]

        def source_metrics(root, names):
            calls.append(("source_metrics", str(root), tuple(names)))
            return metrics

        def git_release(root):
            calls.append(("git_release", str(root)))
            return "release-sha"

        def candidate_baseline(metrics_value, policy_value, release):
            calls.append(
                ("candidate_baseline", metrics_value, policy_value, release)
            )
            return candidate

        def validate_baseline(value):
            calls.append(("validate_baseline", value["path"]))
            return configured_baseline

        def evaluate(root, policy_value, baseline_value):
            calls.append(
                ("evaluate", str(root), policy_value, baseline_value)
            )
            return report

        def atomic_json(path, value):
            calls.append(("atomic_json", str(path), value))

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(quality, "parse_args", return_value=args), \
             mock.patch.object(quality, "read_object", side_effect=read_object), \
             mock.patch.object(quality, "validate_policy", side_effect=validate_policy), \
             mock.patch.object(quality, "selected_sources", side_effect=selected_sources), \
             mock.patch.object(quality, "source_metrics", side_effect=source_metrics), \
             mock.patch.object(quality, "git_release", side_effect=git_release), \
             mock.patch.object(quality, "candidate_baseline", side_effect=candidate_baseline), \
             mock.patch.object(quality, "validate_baseline", side_effect=validate_baseline), \
             mock.patch.object(quality, "evaluate", side_effect=evaluate), \
             mock.patch.object(quality, "atomic_json", side_effect=atomic_json), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            result = quality.main()
        return result, stdout.getvalue(), stderr.getvalue(), calls, candidate

    def test_main_print_current_baseline_returns_before_baseline_read(self) -> None:
        args = self.main_args(print_current_baseline=True)
        report = {
            "ok": True,
            "files_scanned": 1,
            "functions_scanned": 1,
            "failures": [],
            "warnings": [],
            "metrics": {},
        }

        result, stdout, stderr, calls, candidate = self.invoke_main(args, report)

        self.assertEqual(result, 0)
        self.assertEqual(
            stdout,
            json.dumps(candidate, indent=2, sort_keys=True) + "\n",
        )
        self.assertEqual(stderr, "")
        self.assertEqual(
            [item[0] for item in calls],
            [
                "read_object",
                "validate_policy",
                "selected_sources",
                "source_metrics",
                "git_release",
                "candidate_baseline",
            ],
        )

    def test_main_preserves_json_healthy_and_failure_rendering(self) -> None:
        healthy = {
            "ok": True,
            "files_scanned": 7,
            "functions_scanned": 11,
            "failures": [],
            "warnings": [{"kind": "warning"}, {"kind": "warning"}],
            "metrics": {"private": "omit"},
        }
        result, stdout, stderr, calls, _ = self.invoke_main(
            self.main_args(),
            healthy,
        )
        self.assertEqual(result, 0)
        self.assertEqual(
            stdout,
            "module quality gate passed: 7 files, 11 Python functions, "
            "2 ratcheting warnings\n",
        )
        self.assertEqual(stderr, "")
        self.assertEqual(
            [item[0] for item in calls[-3:]],
            ["read_object", "validate_baseline", "evaluate"],
        )

        failed = {
            "ok": False,
            "files_scanned": 3,
            "functions_scanned": 5,
            "failures": [
                {
                    "kind": "module_lines",
                    "name": "large.py",
                    "measured": 21,
                    "allowed": 20,
                },
                {"kind": "import_cycle", "name": "a -> b -> a"},
            ],
            "warnings": [],
            "metrics": {"private": "omit"},
        }
        result, stdout, stderr, _, _ = self.invoke_main(
            self.main_args(),
            failed,
        )
        self.assertEqual(result, 1)
        self.assertEqual(stdout, "")
        self.assertEqual(
            stderr,
            "module_lines: large.py measured=21 allowed=20\n"
            "import_cycle: a -> b -> a\n",
        )

        result, stdout, stderr, _, _ = self.invoke_main(
            self.main_args(json=True),
            failed,
        )
        self.assertEqual(result, 1)
        self.assertEqual(stderr, "")
        public = {key: value for key, value in failed.items() if key != "metrics"}
        self.assertEqual(stdout, json.dumps(public, indent=2, sort_keys=True) + "\n")
        self.assertNotIn("private", stdout)

    def test_main_preserves_baseline_update_and_error_boundaries(self) -> None:
        healthy = {
            "ok": True,
            "files_scanned": 1,
            "functions_scanned": 2,
            "failures": [],
            "warnings": [],
            "metrics": {},
        }
        result, stdout, stderr, calls, candidate = self.invoke_main(
            self.main_args(update_baseline=True),
            healthy,
        )
        self.assertEqual((result, stderr), (0, ""))
        self.assertIn("module quality gate passed", stdout)
        self.assertEqual(calls[-1], ("atomic_json", "/quality-baseline.json", candidate))
        self.assertEqual(calls[-2][0], "evaluate")

        failed = dict(healthy, ok=False)
        result, stdout, stderr, calls, _ = self.invoke_main(
            self.main_args(update_baseline=True),
            failed,
        )
        self.assertEqual(result, 2)
        self.assertEqual(stdout, "")
        self.assertEqual(
            stderr,
            "module quality configuration error: refusing baseline update "
            "because current debt exceeds the baseline\n",
        )
        self.assertNotIn("atomic_json", [item[0] for item in calls])

        with mock.patch.object(quality, "parse_args", return_value=self.main_args()), \
             mock.patch.object(
                 quality,
                 "read_object",
                 side_effect=quality.QualityConfigError("bad-policy"),
             ), redirect_stdout(io.StringIO()) as stdout, \
             redirect_stderr(io.StringIO()) as stderr:
            result = quality.main()
        self.assertEqual(result, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "module quality configuration error: bad-policy\n",
        )

        with mock.patch.object(quality, "parse_args", side_effect=RuntimeError("outside")):
            with self.assertRaisesRegex(RuntimeError, "outside"):
                quality.main()

    def test_dependency_graph_uses_longest_unique_alias_and_skips_self(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src/pkg").mkdir(parents=True)
            (root / "other").mkdir()
            (root / "src/consumer.py").write_text(
                "import pkg.sub.deep\n"
                "import shared\n"
                "import consumer\n"
                "from .pkg import item\n",
                encoding="utf-8",
            )
            (root / "src/pkg.py").write_text("value = 1\n", encoding="utf-8")
            (root / "src/pkg/sub.py").write_text("value = 2\n", encoding="utf-8")
            (root / "src/shared.py").write_text("value = 3\n", encoding="utf-8")
            (root / "other/shared.py").write_text("value = 4\n", encoding="utf-8")
            (root / "src/ignored.js").write_text("value = 5;\n", encoding="utf-8")
            names = [
                "src/consumer.py",
                "src/pkg.py",
                "src/pkg/sub.py",
                "src/shared.py",
                "other/shared.py",
                "src/ignored.js",
            ]
            configured = policy(python_import_roots=["src", "other"])

            graph = quality.dependency_graph(root, iter(names), configured)
            second = quality.dependency_graph(root, iter(names), configured)

        self.assertEqual(
            list(graph),
            [
                "src/consumer.py",
                "src/pkg.py",
                "src/pkg/sub.py",
                "src/shared.py",
                "other/shared.py",
            ],
        )
        self.assertEqual(
            graph,
            {
                "src/consumer.py": {"src/pkg/sub.py", "src/pkg.py"},
                "src/pkg.py": set(),
                "src/pkg/sub.py": set(),
                "src/shared.py": set(),
                "other/shared.py": set(),
            },
        )
        self.assertEqual(graph, second)
        for name in graph:
            self.assertIsNot(graph[name], second[name])

    def test_dependency_graph_preserves_composition_and_failure_order(self) -> None:
        calls = []

        class SourceNames:
            def __iter__(self):
                calls.append(("source_names", "iter"))
                yield "a.py"
                yield "ignored.js"
                yield "b.py"

        class SourcePath:
            def __init__(self, name):
                self.name = name

            def read_text(self, *, encoding):
                calls.append(("read_text", self.name, encoding))
                return "source:" + self.name

        class Root:
            def __truediv__(self, name):
                calls.append(("join", name))
                return SourcePath(name)

        trees = {"a.py": object(), "b.py": object()}

        def aliases(path, roots):
            calls.append(("module_aliases", path, tuple(roots)))
            return {"alpha" if path == "a.py" else "beta"}

        def parse(source, *, filename):
            calls.append(("parse", source, filename))
            return trees[filename]

        def imports(tree, current):
            name = "a.py" if tree is trees["a.py"] else "b.py"
            calls.append(("imported_names", name, tuple(sorted(current))))
            return ["beta.deep", "alpha"] if name == "a.py" else []

        with mock.patch.object(quality, "module_aliases", side_effect=aliases), \
             mock.patch.object(quality.ast, "parse", side_effect=parse), \
             mock.patch.object(quality, "imported_names", side_effect=imports):
            graph = quality.dependency_graph(
                Root(),
                SourceNames(),
                {"python_import_roots": ["root"]},
            )

        self.assertEqual(graph, {"a.py": {"b.py"}, "b.py": set()})
        self.assertEqual(
            calls,
            [
                ("source_names", "iter"),
                ("module_aliases", "a.py", ("root",)),
                ("module_aliases", "b.py", ("root",)),
                ("join", "a.py"),
                ("read_text", "a.py", "utf-8"),
                ("parse", "source:a.py", "a.py"),
                ("module_aliases", "a.py", ("root",)),
                ("imported_names", "a.py", ("alpha",)),
                ("join", "b.py"),
                ("read_text", "b.py", "utf-8"),
                ("parse", "source:b.py", "b.py"),
                ("module_aliases", "b.py", ("root",)),
                ("imported_names", "b.py", ("beta",)),
            ],
        )

        calls.clear()
        with mock.patch.object(
            quality,
            "string_list",
            side_effect=RuntimeError("roots-stop"),
        ), mock.patch.object(quality, "module_aliases") as alias_mock:
            with self.assertRaisesRegex(RuntimeError, "roots-stop"):
                quality.dependency_graph(
                    Root(),
                    SourceNames(),
                    {"python_import_roots": ["root"]},
                )
        self.assertEqual(calls, [("source_names", "iter")])
        alias_mock.assert_not_called()

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
