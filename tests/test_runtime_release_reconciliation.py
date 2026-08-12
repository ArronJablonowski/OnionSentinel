from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "operations/runtime_release_reconciliation.py"
SPEC = importlib.util.spec_from_file_location("runtime_release_reconciliation", MODULE_PATH)
assert SPEC and SPEC.loader
reconciliation = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reconciliation
SPEC.loader.exec_module(reconciliation)


INSTALLER = r'''#!/bin/zsh
for tree in lib routes services repositories jobs composition; do
  cp -R "$source" "$ALERT_STORE_STAGE_DIR/$tree"
done
cp "$REPO_DIR/n8n/bin/app.py" "$STACK_DIR/bin/app.py"
cp "$REPO_DIR/n8n/.env.example" "$STACK_DIR/.env"
cp "$REPO_DIR/n8n/config/private.json" "$STACK_DIR/config/private.json"
cp "$REPO_DIR/n8n/agent-memory/$memory_file" "$STACK_DIR/soc-alerts/agent-memory/$memory_file"
/usr/bin/python3 "$STACK_DIR/bin/install-investigation-query-runtime.py" \
  --repo-root "$REPO_DIR"
/usr/bin/python3 "$REPO_DIR/n8n/bin/install-ai-runtime-package.py" \
  --source "$REPO_DIR/n8n/onion_sentinel" \
  --destination "$STACK_DIR/onion_sentinel"
cp -R "$REPO_DIR/onion-sentinel-dashboard/assets/." "$DASHBOARD_RUNTIME_DIR/assets/"
'''


class RuntimeReleaseReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.runtime = self.root / "runtime"
        self.repo.mkdir()
        self.runtime.mkdir()
        self._write("n8n/bin/install-macstudio-stack.zsh", INSTALLER)
        self._write("n8n/bin/app.py", "print('safe')\n")
        self._write("n8n/.env.example", "TOKEN=placeholder\n")
        self._write("n8n/config/private.json", '{"secret":"placeholder"}\n')
        self._write("n8n/bin/install-investigation-query-runtime.py", "# helper\n")
        self._write(
            "n8n/compat/investigation-pivots-v1/investigation_query_contract.py",
            'INVESTIGATION_QUERY_CONTRACT = "v1"\n',
        )
        self._write(
            "n8n/compat/investigation-pivots-v1/collect-investigation-pivots.py",
            "# v1 collector\n",
        )
        self._write(
            "n8n/bin/investigation_query_contract.py",
            'INVESTIGATION_QUERY_CONTRACT = "v2"\n',
        )
        self._write("n8n/bin/collect-investigation-pivots.py", "# v2 collector\n")
        for name in reconciliation.V2_QUERY_DEPENDENCIES:
            self._write(f"n8n/bin/{name}", f"# {name}\n")
        self._write("n8n/onion_sentinel/__init__.py", "VALUE = 1\n")
        self._write("onion-sentinel-dashboard/assets/logo.svg", "<svg/>\n")
        subprocess.run(("git", "init", "-q"), cwd=self.repo, check=True)
        subprocess.run(
            ("git", "config", "user.email", "test@example.invalid"),
            cwd=self.repo,
            check=True,
        )
        subprocess.run(
            ("git", "config", "user.name", "Test"), cwd=self.repo, check=True
        )
        subprocess.run(("git", "add", "."), cwd=self.repo, check=True)
        subprocess.run(("git", "commit", "-qm", "fixture"), cwd=self.repo, check=True)
        self.commit = subprocess.check_output(
            ("git", "rev-parse", "HEAD"), cwd=self.repo, text=True
        ).strip()
        self._runtime_write("bin/app.py", "print('safe')\n")
        self._runtime_write("onion_sentinel/__init__.py", "VALUE = 1\n")
        self._runtime_write("onion-sentinel-dashboard/assets/logo.svg", "<svg/>\n")
        self._runtime_write(
            "bin/investigation_query_contract.py",
            'INVESTIGATION_QUERY_CONTRACT = "v1"\n',
        )
        self._runtime_write("bin/collect-investigation-pivots.py", "# v1 collector\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self, relative: str, value: str) -> None:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)

    def _runtime_write(self, relative: str, value: str) -> None:
        path = self.runtime / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)

    def _reconcile(self, **overrides: object) -> dict[str, object]:
        values = {
            "repo_root": self.repo,
            "stack_dir": self.runtime,
            "revision": self.commit,
            "expected_release_id": self.commit,
            "live_release_id": self.commit,
        }
        values.update(overrides)
        return reconciliation.reconcile(**values)

    def test_matching_manifest_is_deterministic_and_excludes_sensitive_paths(self) -> None:
        first = self._reconcile()
        second = self._reconcile()
        self.assertTrue(first["ok"])
        self.assertEqual(first, second)
        self.assertEqual(first["counts"], {"match": 5, "mismatch": 0, "missing": 0, "unsafe": 0})
        self.assertEqual(first["investigation_query_contract"], "v1")
        runtime_paths = [entry["runtime"] for entry in first["entries"]]
        self.assertEqual(runtime_paths, sorted(runtime_paths))
        self.assertNotIn(".env", runtime_paths)
        self.assertFalse(any(path.startswith("config/") for path in runtime_paths))
        canonical = json.dumps(first["entries"], sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(first["manifest_sha256"], hashlib.sha256(canonical).hexdigest())

    def test_mismatch_missing_and_symlink_are_fail_closed(self) -> None:
        (self.runtime / "bin/app.py").write_text("changed\n")
        (self.runtime / "onion_sentinel/__init__.py").unlink()
        logo = self.runtime / "onion-sentinel-dashboard/assets/logo.svg"
        logo.unlink()
        logo.symlink_to(self.repo / "onion-sentinel-dashboard/assets/logo.svg")
        report = self._reconcile()
        self.assertFalse(report["ok"])
        self.assertEqual(report["counts"], {"match": 2, "mismatch": 1, "missing": 1, "unsafe": 1})
        self.assertTrue(all("content" not in entry for entry in report["entries"]))

    def test_excluded_runtime_paths_are_never_opened(self) -> None:
        observed: list[str] = []
        original = reconciliation._hash_runtime_file

        def recording(root: Path, relative: str) -> tuple[str, int]:
            observed.append(relative)
            return original(root, relative)

        with mock.patch.object(reconciliation, "_hash_runtime_file", side_effect=recording):
            self.assertTrue(self._reconcile()["ok"])
        self.assertFalse(any(reconciliation._excluded(path) for path in observed))

    def test_release_mismatch_fails_before_runtime_access(self) -> None:
        with mock.patch.object(reconciliation, "_hash_runtime_file") as runtime_hash:
            with self.assertRaisesRegex(reconciliation.ReconciliationError, "live release"):
                self._reconcile(live_release_id="0" * 40)
        runtime_hash.assert_not_called()

    def test_unclassified_installer_copy_fails_coverage(self) -> None:
        changed = INSTALLER + 'cp "$REPO_DIR/new/tool.py" "$UNKNOWN_ROOT/tool.py"\n'
        with self.assertRaisesRegex(reconciliation.ReconciliationError, "unclassified"):
            reconciliation.validate_installer_coverage(changed)

    def test_unclassified_non_copy_runtime_operation_fails_coverage(self) -> None:
        changed = INSTALLER + 'deploy "$REPO_DIR/new/tool.py" "$STACK_DIR/bin/tool.py"\n'
        with self.assertRaisesRegex(reconciliation.ReconciliationError, "unclassified"):
            reconciliation.validate_installer_coverage(changed)

    def test_indirect_repository_source_cannot_bypass_coverage(self) -> None:
        changed = INSTALLER + 'source="$REPO_DIR/new"\ncp "$source" "$target"\n'
        with self.assertRaisesRegex(reconciliation.ReconciliationError, "unclassified"):
            reconciliation.validate_installer_coverage(changed)

    def test_v2_contract_adds_versioned_dependencies(self) -> None:
        self._runtime_write(
            "bin/investigation_query_contract.py",
            'INVESTIGATION_QUERY_CONTRACT = "v2"\n',
        )
        self._runtime_write("bin/collect-investigation-pivots.py", "# v2 collector\n")
        for name in reconciliation.V2_QUERY_DEPENDENCIES:
            self._runtime_write(f"bin/{name}", f"# {name}\n")
        report = self._reconcile()
        self.assertTrue(report["ok"])
        self.assertEqual(report["investigation_query_contract"], "v2")
        self.assertEqual(report["counts"]["match"], 10)

    def test_unrecognized_contract_fails_without_claiming_a_version(self) -> None:
        self._runtime_write("bin/investigation_query_contract.py", "corrupt\n")
        report = self._reconcile()
        self.assertFalse(report["ok"])
        self.assertEqual(report["investigation_query_contract"], "unrecognized")

    def test_symlinked_runtime_parent_cannot_escape_root(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "app.py").write_text("print('safe')\n")
        app_dir = self.runtime / "bin"
        for child in app_dir.iterdir():
            child.unlink()
        app_dir.rmdir()
        app_dir.symlink_to(outside, target_is_directory=True)
        report = self._reconcile()
        app = next(entry for entry in report["entries"] if entry["runtime"] == "bin/app.py")
        self.assertEqual(app["status"], "unsafe")


if __name__ == "__main__":
    unittest.main()
