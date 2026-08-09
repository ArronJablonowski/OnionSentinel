#!/usr/bin/env python3
"""Contracts for the stable AI package and its atomic installer."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
DASHBOARD_ROOT = ROOT / "onion-sentinel-dashboard"
INSTALLER = N8N_ROOT / "bin" / "install-ai-runtime-package.py"
if str(N8N_ROOT) not in sys.path:
    sys.path.insert(0, str(N8N_ROOT))

from onion_sentinel.composition import invoke_legacy_entrypoint
from onion_sentinel.contracts.errors import BoundaryError, ErrorReceipt
from onion_sentinel.contracts.models import ModelRoute, QueryReceipt, QueryRequest
from onion_sentinel.runtime import RuntimeDependencies


def load_installer():
    spec = importlib.util.spec_from_file_location("install_ai_runtime_package", INSTALLER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AiRuntimePackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = load_installer()

    def test_composition_root_preserves_integer_exit_code(self) -> None:
        calls = []

        def main():
            calls.append("called")
            return 7

        self.assertEqual(invoke_legacy_entrypoint({"main": main}), 7)
        self.assertEqual(calls, ["called"])

    def test_legacy_cli_help_runs_through_package_composition_root(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(N8N_ROOT / "bin/run-local-ai-analysis.py"), "--help"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("usage:", completed.stdout.lower())

    def test_composition_root_rejects_missing_or_invalid_exit_contract(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "callable main"):
            invoke_legacy_entrypoint({})

        def main():
            return None

        with self.assertRaisesRegex(RuntimeError, "integer exit code"):
            invoke_legacy_entrypoint({"main": main})

    def test_boundary_error_never_exposes_private_diagnostic(self) -> None:
        receipt = ErrorReceipt(
            code="provider_timeout",
            category="provider",
            retryable=True,
            public_message="provider request timed out",
        )
        error = BoundaryError(
            receipt,
            diagnostic="secret-bearing subprocess stderr",
            context={"private": "value"},
        )
        public = error.public_dict()
        self.assertEqual(public["code"], "provider_timeout")
        self.assertNotIn("diagnostic", public)
        self.assertNotIn("context", public)
        self.assertNotIn("secret-bearing", str(public))

    def test_read_only_query_receipt_fails_closed(self) -> None:
        request = QueryRequest(
            query_id="q1",
            backend="security_onion",
            operation="network_flow",
            parameters={"source_ip": "192.0.2.10"},
            authorization_ref="authorization:synthetic",
        )
        with self.assertRaisesRegex(ValueError, "read-only"):
            QueryReceipt(
                request=request,
                status="ok",
                read_only=False,
                evidence={},
            )

    def test_model_route_and_runtime_dependencies_are_deterministic(self) -> None:
        route = ModelRoute("codex-cli", "gpt-5.6-sol", "XHIGH")
        self.assertEqual(route.canonical, "codex-cli:gpt-5.6-sol:xhigh")
        dependencies = RuntimeDependencies(
            id_factory=lambda: "fixed-id",
            clock=lambda: None,
        )
        self.assertEqual(dependencies.id_factory(), "fixed-id")
        with self.assertRaisesRegex(RuntimeError, "filesystem dependencies"):
            dependencies.require_filesystem()
        with self.assertRaisesRegex(RuntimeError, "external I/O dependencies"):
            dependencies.require_external_io()

    def test_atomic_installer_replaces_complete_tree_without_temp_debris(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            destination = root / "onion_sentinel"
            destination.mkdir()
            (destination / "old.txt").write_text("old", encoding="utf-8")

            self.installer.install_package(N8N_ROOT / "onion_sentinel", destination)

            self.assertTrue((destination / "__init__.py").is_file())
            self.assertFalse((destination / "old.txt").exists())
            self.assertEqual(list(destination.rglob("__pycache__")), [])
            self.assertEqual(
                list(root.glob(".onion-sentinel-package.*")),
                [],
            )
            self.assertEqual(
                list(root.glob(".onion-sentinel-package-backup.*")),
                [],
            )

    def test_atomic_installer_validates_with_production_system_python(self) -> None:
        production_python = Path("/usr/bin/python3")
        if not production_python.is_file():
            self.skipTest("production system Python is unavailable")
        with tempfile.TemporaryDirectory() as temp_name:
            destination = Path(temp_name) / "onion_sentinel"
            completed = subprocess.run(
                [
                    str(production_python),
                    str(INSTALLER),
                    "--source",
                    str(N8N_ROOT / "onion_sentinel"),
                    "--destination",
                    str(destination),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue((destination / "__init__.py").is_file())
            self.assertEqual(list(destination.rglob("__pycache__")), [])

    def test_dashboard_imports_with_production_system_python(self) -> None:
        production_python = Path("/usr/bin/python3")
        if not production_python.is_file():
            self.skipTest("production system Python is unavailable")
        completed = subprocess.run(
            [
                str(production_python),
                "-c",
                "import report_portal; import onion_sentinel_server",
            ],
            cwd=DASHBOARD_ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_invalid_source_leaves_existing_runtime_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            source = root / "onion_sentinel"
            destination = root / "runtime" / "onion_sentinel"
            source.mkdir()
            destination.mkdir(parents=True)
            marker = destination / "release.txt"
            marker.write_text("known-good", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "incomplete"):
                self.installer.install_package(source, destination)

            self.assertEqual(marker.read_text(encoding="utf-8"), "known-good")

    def test_failed_staged_import_leaves_existing_runtime_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            source = root / "source" / "onion_sentinel"
            destination = root / "runtime" / "onion_sentinel"
            source.mkdir(parents=True)
            destination.mkdir(parents=True)
            (source / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
            marker = destination / "release.txt"
            marker.write_text("known-good", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "import validation failed"):
                self.installer.install_package(source, destination)

            self.assertEqual(marker.read_text(encoding="utf-8"), "known-good")
            self.assertEqual(list((root / "runtime").glob(".*package*")), [])

    def test_unlisted_staged_module_import_failure_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            source = root / "source" / "onion_sentinel"
            destination = root / "runtime" / "onion_sentinel"
            source.mkdir(parents=True)
            destination.mkdir(parents=True)
            (source / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
            (source / "unlisted.py").write_text(
                "raise RuntimeError('unlisted import failed')\n",
                encoding="utf-8",
            )
            marker = destination / "release.txt"
            marker.write_text("known-good", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "import validation failed"):
                self.installer.install_package(source, destination)

            self.assertEqual(marker.read_text(encoding="utf-8"), "known-good")
            self.assertEqual(list((root / "runtime").glob(".*package*")), [])


if __name__ == "__main__":
    unittest.main()
