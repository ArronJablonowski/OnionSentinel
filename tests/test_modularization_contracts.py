import ast
import json
from pathlib import Path
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
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }


class ModularizationCompatibilityContractTests(unittest.TestCase):
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

    def test_security_and_compatibility_invariants_are_explicit(self) -> None:
        invariants = "\n".join(load_contract()["stable_service_contracts"])
        self.assertIn("read-only", invariants)
        self.assertIn("HTTP route", invariants)
        self.assertIn("launchd", invariants)
        self.assertIn("versioned migrations", invariants)


if __name__ == "__main__":
    unittest.main()
