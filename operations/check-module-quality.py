#!/usr/bin/env python3
"""Ratcheting source-size, Python-complexity, and import-boundary checks."""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Iterable


POLICY_SCHEMA = "onion-sentinel-module-quality-policy-v1"
BASELINE_SCHEMA = "onion-sentinel-module-quality-baseline-v1"
SOURCE_SUFFIXES = frozenset({".py", ".js", ".mjs", ".cjs"})


class QualityConfigError(RuntimeError):
    """A quality policy or baseline is malformed."""


def read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise QualityConfigError(f"cannot read valid JSON object: {path}") from exc
    if not isinstance(value, dict):
        raise QualityConfigError(f"JSON root must be an object: {path}")
    return value


def positive_integer(policy: dict[str, Any], name: str) -> int:
    value = policy.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise QualityConfigError(f"{name} must be a positive integer")
    return value


def string_list(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise QualityConfigError(f"{name} must be a list of non-empty strings")
    return list(value)


def validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    if policy.get("schema") != POLICY_SCHEMA:
        raise QualityConfigError("unsupported module quality policy schema")
    for name in (
        "module_target_lines",
        "new_module_max_lines",
        "absolute_new_file_max_lines",
        "function_target_lines",
        "new_function_max_lines",
        "complexity_target",
        "new_complexity_max",
    ):
        positive_integer(policy, name)
    if policy["module_target_lines"] > policy["new_module_max_lines"]:
        raise QualityConfigError("module target cannot exceed its enforced limit")
    if policy["new_module_max_lines"] > policy["absolute_new_file_max_lines"]:
        raise QualityConfigError("module limit cannot exceed the absolute limit")
    if policy["function_target_lines"] > policy["new_function_max_lines"]:
        raise QualityConfigError("function target cannot exceed its enforced limit")
    if policy["complexity_target"] > policy["new_complexity_max"]:
        raise QualityConfigError("complexity target cannot exceed its enforced limit")
    string_list(policy.get("include"), "include")
    string_list(policy.get("exclude"), "exclude")
    string_list(policy.get("python_import_roots"), "python_import_roots")
    rules = policy.get("forbidden_dependencies")
    if not isinstance(rules, list):
        raise QualityConfigError("forbidden_dependencies must be a list")
    for rule in rules:
        if not isinstance(rule, dict):
            raise QualityConfigError("dependency rule must be an object")
        string_list([rule.get("from"), rule.get("to")], "dependency rule")
    return policy


def validate_baseline(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("schema") != BASELINE_SCHEMA:
        raise QualityConfigError("unsupported module quality baseline schema")
    for name in ("files", "functions"):
        if not isinstance(value.get(name), dict):
            raise QualityConfigError(f"baseline {name} must be an object")
    return value


def tracked_files(root: Path) -> list[str]:
    try:
        tracked = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
        )
        untracked = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "--others",
                "--exclude-standard",
                "-z",
            ],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return sorted(
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file()
        )
    return sorted({
        item.decode("utf-8")
        for item in (tracked.stdout + untracked.stdout).split(b"\0")
        if item
    })


def matches_any(path: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def selected_sources(root: Path, policy: dict[str, Any]) -> list[str]:
    include = string_list(policy["include"], "include")
    exclude = string_list(policy["exclude"], "exclude")
    return [
        name
        for name in tracked_files(root)
        if Path(name).suffix in SOURCE_SUFFIXES
        and matches_any(name, include)
        and not matches_any(name, exclude)
        and (root / name).is_file()
    ]


class FunctionCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.scope: list[str] = []
        self.functions: dict[str, dict[str, int]] = {}

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def _visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        qualified = ".".join([*self.scope, node.name])
        if qualified in self.functions:
            raise QualityConfigError(f"duplicate function identity: {qualified}")
        self.functions[qualified] = {
            "lines": node.end_lineno - node.lineno + 1,
            "complexity": function_complexity(node),
        }
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function


class ComplexityVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.value = 1

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_If(self, node: ast.If) -> None:
        self.value += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.value += 1
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_While(self, node: ast.While) -> None:
        self.value += 1
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        self.value += len(node.handlers)
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self.value += max(0, len(node.values) - 1)
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.value += 1
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        self.value += max(0, len(node.cases) - 1)
        self.generic_visit(node)

    def _visit_comprehension(self, generators: list[ast.comprehension]) -> None:
        self.value += sum(1 + len(generator.ifs) for generator in generators)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node.generators)
        self.generic_visit(node)

    visit_SetComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node.generators)
        self.generic_visit(node)


def function_complexity(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    visitor = ComplexityVisitor()
    for child in node.body:
        visitor.visit(child)
    return visitor.value


def source_metrics(root: Path, names: Iterable[str]) -> dict[str, Any]:
    metrics: dict[str, Any] = {"files": {}, "functions": {}}
    for name in names:
        path = root / name
        source = path.read_text(encoding="utf-8")
        metrics["files"][name] = {"lines": len(source.splitlines())}
        if path.suffix != ".py":
            continue
        try:
            tree = ast.parse(source, filename=name)
        except SyntaxError as exc:
            raise QualityConfigError(f"cannot parse Python source: {name}") from exc
        collector = FunctionCollector()
        collector.visit(tree)
        for qualified, values in collector.functions.items():
            metrics["functions"][f"{name}::{qualified}"] = values
    return metrics


def candidate_baseline(
    metrics: dict[str, Any],
    policy: dict[str, Any],
    release: str,
) -> dict[str, Any]:
    file_limit = positive_integer(policy, "new_module_max_lines")
    function_limit = positive_integer(policy, "new_function_max_lines")
    complexity_limit = positive_integer(policy, "new_complexity_max")
    files = {
        name: {"max_lines": values["lines"]}
        for name, values in metrics["files"].items()
        if values["lines"] > file_limit
    }
    functions: dict[str, dict[str, int]] = {}
    for name, values in metrics["functions"].items():
        debt: dict[str, int] = {}
        if values["lines"] > function_limit:
            debt["max_lines"] = values["lines"]
        if values["complexity"] > complexity_limit:
            debt["max_complexity"] = values["complexity"]
        if debt:
            functions[name] = debt
    return {
        "schema": BASELINE_SCHEMA,
        "source_release": release,
        "files": dict(sorted(files.items())),
        "functions": dict(sorted(functions.items())),
    }


def issue(kind: str, name: str, measured: int, allowed: int) -> dict[str, Any]:
    return {
        "kind": kind,
        "name": name,
        "measured": measured,
        "allowed": allowed,
    }


def _append_function_metric_issue(
    failures: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
    kind: str,
    name: str,
    values: dict[str, int],
    metric: str,
    allowed: int,
    target: int,
) -> None:
    if values[metric] > allowed:
        failures.append(issue(kind, name, values[metric], allowed))
    elif values[metric] > target:
        warnings.append(issue(kind, name, values[metric], target))


def metric_issues(
    metrics: dict[str, Any],
    policy: dict[str, Any],
    baseline: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    failures: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    file_target = positive_integer(policy, "module_target_lines")
    file_limit = positive_integer(policy, "new_module_max_lines")
    function_target = positive_integer(policy, "function_target_lines")
    function_limit = positive_integer(policy, "new_function_max_lines")
    complexity_target = positive_integer(policy, "complexity_target")
    complexity_limit = positive_integer(policy, "new_complexity_max")
    for name, values in metrics["files"].items():
        measured = values["lines"]
        debt = baseline["files"].get(name)
        allowed = debt.get("max_lines") if isinstance(debt, dict) else file_limit
        if measured > allowed:
            failures.append(issue("module_lines", name, measured, allowed))
        elif measured > file_target:
            warnings.append(issue("module_lines", name, measured, file_target))
    for name, values in metrics["functions"].items():
        debt = baseline["functions"].get(name)
        debt = debt if isinstance(debt, dict) else {}
        allowed_lines = debt.get("max_lines", function_limit)
        allowed_complexity = debt.get("max_complexity", complexity_limit)
        _append_function_metric_issue(
            failures,
            warnings,
            "function_lines",
            name,
            values,
            "lines",
            allowed_lines,
            function_target,
        )
        _append_function_metric_issue(
            failures,
            warnings,
            "function_complexity",
            name,
            values,
            "complexity",
            allowed_complexity,
            complexity_target,
        )
    return failures, warnings


def module_aliases(path: str, roots: Iterable[str]) -> set[str]:
    aliases: set[str] = set()
    source = Path(path)
    if source.suffix != ".py" or "-" in source.stem:
        return aliases
    aliases.add(source.stem)
    for root in roots:
        prefix = root.rstrip("/") + "/"
        if not path.startswith(prefix):
            continue
        relative = path[len(prefix) : -3]
        parts = [part for part in relative.split("/") if part != "__init__"]
        if parts and all(part.isidentifier() for part in parts):
            aliases.add(".".join(parts))
    return aliases


def relative_import_names(
    node: ast.ImportFrom,
    current_modules: set[str],
) -> set[str]:
    names: set[str] = set()
    for current in current_modules:
        package = current.split(".")[:-1]
        remove = max(0, node.level - 1)
        if remove > len(package):
            continue
        base = package[: len(package) - remove] if remove else package
        if node.module:
            names.add(".".join([*base, node.module]))
        else:
            for alias in node.names:
                names.add(".".join([*base, alias.name]))
    return {name for name in names if name}


def imported_names(tree: ast.Module, current_modules: set[str]) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                names.add(node.module)
            elif node.level:
                names.update(relative_import_names(node, current_modules))
    return names


def _dependency_candidates(
    imported: str,
    aliases: dict[str, set[str]],
) -> set[str]:
    candidates: set[str] = set()
    parts = imported.split(".")
    for length in range(len(parts), 0, -1):
        candidates = aliases.get(".".join(parts[:length]), set())
        if candidates:
            break
    return candidates


def dependency_graph(
    root: Path,
    source_names: Iterable[str],
    policy: dict[str, Any],
) -> dict[str, set[str]]:
    python_names = [name for name in source_names if name.endswith(".py")]
    roots = string_list(policy["python_import_roots"], "python_import_roots")
    aliases: dict[str, set[str]] = {}
    for path in python_names:
        for alias in module_aliases(path, roots):
            aliases.setdefault(alias, set()).add(path)
    graph = {name: set() for name in python_names}
    for path in python_names:
        tree = ast.parse((root / path).read_text(encoding="utf-8"), filename=path)
        current_modules = module_aliases(path, roots)
        for imported in imported_names(tree, current_modules):
            candidates = _dependency_candidates(imported, aliases)
            if len(candidates) == 1:
                target = next(iter(candidates))
                if target != path:
                    graph[path].add(target)
    return graph


def graph_issues(
    graph: dict[str, set[str]],
    policy: dict[str, Any],
) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    state: dict[str, int] = {}
    stack: list[str] = []
    cycles: set[tuple[str, ...]] = set()

    def visit(node: str) -> None:
        state[node] = 1
        stack.append(node)
        for target in sorted(graph[node]):
            if state.get(target, 0) == 0:
                visit(target)
            elif state.get(target) == 1:
                start = stack.index(target)
                cycles.add(tuple(stack[start:] + [target]))
        stack.pop()
        state[node] = 2

    for node in sorted(graph):
        if state.get(node, 0) == 0:
            visit(node)
    for cycle in sorted(cycles):
        failures.append(
            {"kind": "import_cycle", "name": " -> ".join(cycle)}
        )
    for source, targets in graph.items():
        for target in targets:
            for rule in policy["forbidden_dependencies"]:
                if fnmatch.fnmatch(source, rule["from"]) and fnmatch.fnmatch(
                    target, rule["to"]
                ):
                    failures.append(
                        {
                            "kind": "forbidden_dependency",
                            "name": f"{source} -> {target}",
                        }
                    )
    return failures


def git_release(root: Path) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unversioned"


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def evaluate(
    root: Path,
    policy: dict[str, Any],
    baseline: dict[str, Any],
) -> dict[str, Any]:
    names = selected_sources(root, policy)
    metrics = source_metrics(root, names)
    failures, warnings = metric_issues(metrics, policy, baseline)
    failures.extend(graph_issues(dependency_graph(root, names, policy), policy))
    return {
        "ok": not failures,
        "files_scanned": len(metrics["files"]),
        "functions_scanned": len(metrics["functions"]),
        "failures": failures,
        "warnings": warnings,
        "metrics": metrics,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path(__file__).resolve().parent / "quality" / "module-quality-policy.json",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path(__file__).resolve().parent / "quality" / "module-quality-baseline.json",
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--print-current-baseline", action="store_true")
    parser.add_argument("--update-baseline", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        root = args.root.expanduser().resolve()
        policy = validate_policy(read_object(args.policy.expanduser().resolve()))
        baseline_path = args.baseline.expanduser().resolve()
        names = selected_sources(root, policy)
        metrics = source_metrics(root, names)
        candidate = candidate_baseline(metrics, policy, git_release(root))
        if args.print_current_baseline:
            print(json.dumps(candidate, indent=2, sort_keys=True))
            return 0
        baseline = validate_baseline(read_object(baseline_path))
        report = evaluate(root, policy, baseline)
        if args.update_baseline:
            if not report["ok"]:
                raise QualityConfigError(
                    "refusing baseline update because current debt exceeds the baseline"
                )
            atomic_json(baseline_path, candidate)
        public_report = {key: value for key, value in report.items() if key != "metrics"}
        if args.json:
            print(json.dumps(public_report, indent=2, sort_keys=True))
        elif report["ok"]:
            print(
                "module quality gate passed: "
                f"{report['files_scanned']} files, "
                f"{report['functions_scanned']} Python functions, "
                f"{len(report['warnings'])} ratcheting warnings"
            )
        else:
            for item in report["failures"]:
                measured = f" measured={item['measured']} allowed={item['allowed']}" if "measured" in item else ""
                print(f"{item['kind']}: {item['name']}{measured}", file=sys.stderr)
        return 0 if report["ok"] else 1
    except QualityConfigError as exc:
        print(f"module quality configuration error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
