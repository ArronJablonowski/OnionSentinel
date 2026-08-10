import ast
import builtins
import importlib
import json
from pathlib import Path
import subprocess
import symtable
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "operations" / "quality" / "modularization-contracts.json"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"
QUERY_RUNTIME_INSTALLER_PATH = (
    ROOT / "n8n" / "bin" / "install-investigation-query-runtime.py"
)


def load_contract() -> dict:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def top_level_symbols(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    symbols: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbols.add(node.name)
        elif isinstance(node, ast.Assign):
            symbols.update(
                target.id for target in node.targets if isinstance(target, ast.Name)
            )
            if any(
                isinstance(target, ast.Name) and target.id == "__all__"
                for target in node.targets
            ):
                try:
                    exported = ast.literal_eval(node.value)
                except (TypeError, ValueError):
                    exported = ()
                if isinstance(exported, (list, tuple, set)):
                    symbols.update(str(name) for name in exported)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            symbols.add(node.target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            symbols.update(alias.asname or alias.name for alias in node.names)
    return symbols


def top_level_function(path: Path, name: str) -> ast.FunctionDef:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"missing top-level function: {name}")


class ModularizationCompatibilityContractTests(unittest.TestCase):
    def test_extracted_harness_modules_have_no_undefined_globals(self) -> None:
        allowed = set(dir(builtins)) | {
            "__conditional_annotations__",
            "__file__",
            "__name__",
        }
        for path in sorted((ROOT / "n8n" / "bin").glob("harness_*.py")):
            with self.subTest(path=path.name):
                table = symtable.symtable(
                    path.read_text(encoding="utf-8"), str(path), "exec"
                )
                defined = {
                    symbol.get_name()
                    for symbol in table.get_symbols()
                    if symbol.is_imported()
                    or symbol.is_assigned()
                    or symbol.is_namespace()
                }
                referenced: set[str] = set()

                def collect(scope: symtable.SymbolTable) -> None:
                    referenced.update(
                        symbol.get_name()
                        for symbol in scope.get_symbols()
                        if symbol.is_global() and symbol.is_referenced()
                    )
                    for child in scope.get_children():
                        collect(child)

                collect(table)
                self.assertEqual(sorted(referenced - defined - allowed), [])

    def test_harness_supports_isolated_file_loader_import(self) -> None:
        harness = ROOT / "n8n" / "bin" / "onion_sentinel_harness.py"
        script = (
            "import importlib.util,sys;"
            f"p={str(harness)!r};"
            "s=importlib.util.spec_from_file_location('isolated_harness',p);"
            "m=importlib.util.module_from_spec(s);"
            "sys.modules[s.name]=m;"
            "s.loader.exec_module(m);"
            "assert m.HarnessPolicy and m.HarnessStore and m.HarnessRun;"
            "assert callable(m.start_harness_run)"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_scheduler_supports_isolated_late_bound_composition(self) -> None:
        scheduler = ROOT / "n8n" / "bin" / "auto-run-ai-analysis.py"
        script = (
            "import importlib.util,sys;"
            f"p={str(scheduler)!r};"
            "s=importlib.util.spec_from_file_location('isolated_scheduler',p);"
            "m=importlib.util.module_from_spec(s);"
            "s.loader.exec_module(m);"
            "replacement=lambda *a,**k:None;"
            "m.run_analysis=replacement;"
            "assert m.scheduler_execution_sources().run_analysis is replacement;"
            "assert callable(m.main) and callable(m.parse_args)"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_harness_job_envelope_has_one_dataclass_boundary(self) -> None:
        contracts = ROOT / "n8n" / "bin" / "harness_contracts.py"
        tree = ast.parse(
            contracts.read_text(encoding="utf-8"), filename=str(contracts)
        )
        envelope = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "JobEnvelope"
        )
        self.assertEqual(len(envelope.decorator_list), 1)

        policy_path = ROOT / "n8n" / "bin" / "harness_policy.py"
        policy_tree = ast.parse(
            policy_path.read_text(encoding="utf-8"), filename=str(policy_path)
        )
        policy_classes = {
            node.name: node
            for node in policy_tree.body
            if isinstance(node, ast.ClassDef)
        }
        for name in ("PolicyDecision", "HarnessPolicy"):
            with self.subTest(name=name):
                self.assertEqual(len(policy_classes[name].decorator_list), 1)

    def test_software_inventory_supports_isolated_file_loader_import(self) -> None:
        inventory = ROOT / "onion-sentinel-dashboard" / "software_inventory.py"
        script = (
            "import importlib.util,sys;"
            f"p={str(inventory)!r};"
            "s=importlib.util.spec_from_file_location('isolated_software_inventory',p);"
            "m=importlib.util.module_from_spec(s);"
            "sys.modules[s.name]=m;"
            "s.loader.exec_module(m);"
            "assert callable(m.build_response) and callable(m.load_state)"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_report_portal_supports_isolated_file_loader_import(self) -> None:
        portal = ROOT / "onion-sentinel-dashboard" / "report_portal.py"
        script = (
            "import importlib.util,sys;"
            f"p={str(portal)!r};"
            "s=importlib.util.spec_from_file_location('isolated_report_portal',p);"
            "m=importlib.util.module_from_spec(s);"
            "sys.modules[s.name]=m;"
            "s.loader.exec_module(m);"
            "assert m.PortalHandler and callable(m.main)"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_contract_is_versioned_and_bound_to_a_full_release(self) -> None:
        contract = load_contract()
        self.assertEqual(
            contract["schema"],
            "onion-sentinel-modularization-contracts-v1",
        )
        release = contract["baseline_release"]
        self.assertEqual(len(release), 40)
        self.assertTrue(all(character in "0123456789abcdef" for character in release))

    def test_legacy_python_entry_points_retain_required_symbols(self) -> None:
        for entry in load_contract()["python_entry_points"]:
            with self.subTest(path=entry["path"]):
                path = ROOT / entry["path"]
                self.assertTrue(path.is_file())
                symbols = top_level_symbols(path)
                self.assertEqual(
                    sorted(set(entry["required_symbols"]) - symbols),
                    [],
                )

    def test_direct_copy_entry_points_are_present_in_production_installer(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        for entry in load_contract()["python_entry_points"]:
            if entry["deployment"] not in {
                "direct-copy",
                "dashboard-direct-copy",
            }:
                continue
            source = entry["path"]
            runtime = entry["runtime_path"]
            with self.subTest(path=source):
                self.assertIn(f'$REPO_DIR/{source}', installer)
                self.assertIn(runtime, installer)

    def test_versioned_prompt_builder_remains_in_query_runtime_installer(self) -> None:
        installer = QUERY_RUNTIME_INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertIn(
            'HARDENED_BUILDER = "build-ai-investigation-prompt.py"',
            installer,
        )
        self.assertIn("validate_hardened_builder", installer)
        self.assertIn("_atomic_install", installer)

    def test_python_package_tree_is_complete_importable_and_installed(self) -> None:
        contract = load_contract()
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        original_path = list(sys.path)
        try:
            sys.path.insert(0, str(ROOT / "n8n"))
            for tree in contract["python_package_trees"]:
                self.assertTrue((ROOT / tree["path"] / "__init__.py").is_file())
                self.assertIn(f'$REPO_DIR/{tree["path"]}', installer)
                self.assertIn(tree["runtime_path"], installer)
                self.assertIn(f'$REPO_DIR/{tree["installer"]}', installer)
                for module in tree["required_modules"]:
                    imported = importlib.import_module(module)
                    self.assertIsNotNone(imported)
        finally:
            sys.path[:] = original_path

    def test_ai_runner_delegates_through_package_composition_root(self) -> None:
        runner = (ROOT / "n8n/bin/run-local-ai-analysis.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "from onion_sentinel.composition import invoke_legacy_entrypoint",
            runner,
        )
        self.assertIn("invoke_legacy_entrypoint(globals())", runner)
        package_sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "n8n/onion_sentinel").rglob("*.py")
        )
        self.assertNotIn("run-local-ai-analysis", package_sources)

    def test_ai_runner_query_entry_point_is_a_bounded_runtime_delegate(self) -> None:
        runner_path = ROOT / "n8n/bin/run-local-ai-analysis.py"
        function = top_level_function(
            runner_path,
            "apply_investigation_query_loop",
        )
        self.assertLessEqual(function.end_lineno - function.lineno + 1, 100)
        self.assertFalse(
            any(isinstance(node, (ast.For, ast.While)) for node in ast.walk(function))
        )
        calls = {
            f"{node.func.value.id}.{node.func.attr}"
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
        }
        self.assertIn("module.run", calls)

    def test_ai_runner_query_execution_is_a_bounded_runtime_delegate(self) -> None:
        function = top_level_function(
            ROOT / "n8n/bin/run-local-ai-analysis.py",
            "execute_investigation_query_batch",
        )
        self.assertLessEqual(function.end_lineno - function.lineno + 1, 40)
        self.assertFalse(
            any(isinstance(node, (ast.For, ast.While)) for node in ast.walk(function))
        )
        attributes = {
            node.func.attr for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
        }
        self.assertIn("execute_batch", attributes)

    def test_node_entry_point_matches_package_and_production_installer(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        for entry in load_contract()["node_entry_points"]:
            with self.subTest(path=entry["path"]):
                package = json.loads(
                    (ROOT / entry["package"]).read_text(encoding="utf-8")
                )
                self.assertEqual(package["main"], entry["package_main"])
                self.assertEqual(package["scripts"]["start"], entry["package_start"])
                self.assertIn(f'$REPO_DIR/{entry["path"]}', installer)
                self.assertIn(entry["runtime_path"], installer)

    def test_alert_store_module_trees_are_staged_before_consumers_stop(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertLess(
            installer.index("\nprepare_alert_store_stage\n"),
            installer.index("\ncritical_launch_agents_down\n"),
        )
        for tree in (
            "lib",
            "routes",
            "services",
            "repositories",
            "jobs",
            "composition",
        ):
            self.assertIn(f"n8n/alert_store/$tree", installer)
            self.assertIn(f'ALERT_STORE_STAGE_DIR/$tree', installer)
        self.assertIn("node --check", installer)
        self.assertIn("/usr/bin/rsync -a --delete", installer)
        self.assertIn("Refusing incomplete staged alert-store module tree", installer)

    def test_security_and_compatibility_invariants_are_explicit(self) -> None:
        invariants = "\n".join(load_contract()["stable_service_contracts"])
        self.assertIn("read-only", invariants)
        self.assertIn("HTTP route", invariants)
        self.assertIn("launchd", invariants)
        self.assertIn("versioned migrations", invariants)


if __name__ == "__main__":
    unittest.main()
