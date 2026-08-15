from contextlib import closing
import gc
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import warnings
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n/bin/check-onion-sentinel-readiness.py"
VALIDATOR = ROOT / "operations/validate-credential-governance.py"
CREDENTIAL_CATALOG = ROOT / "operations/security/credential-governance.json"
SPEC = importlib.util.spec_from_file_location("readiness", SCRIPT)
assert SPEC and SPEC.loader
READINESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(READINESS)


class ReadinessTests(unittest.TestCase):
    def make_stack(self, root: Path) -> Path:
        stack = root / "n8n-local"
        for name in ("bin", "config", "run", "logs", "soc-alerts", "alert_store_data"):
            (stack / name).mkdir(parents=True, exist_ok=True)
        (stack / ".env").write_text("ONION_SENTINEL_RELEASE_ID=abcdef1234567\nSECRET=not-read\n")
        os.chmod(stack / ".env", 0o600)
        settings = {
            "agent_models": {"incident-responder": "codex-cli:gpt-5.5:high"},
            "agent_second_opinion_models": {},
            "agent_adjudicator_models": {},
            "codex_cli_path": "/bin/sh",
        }
        for name, value in (
            ("ai_model_settings.json", settings),
            ("investigation_harness_policy.json", {"version": 1}),
            ("investigation_skills.json", {"version": 1}),
            ("incident-evidence.json", {"host": "127.0.0.1", "port": 22}),
        ):
            path = stack / "config" / name
            path.write_text(json.dumps(value))
            os.chmod(path, 0o600 if name == "incident-evidence.json" else 0o644)
        (stack / "bin" / "validate-credential-governance.py").write_bytes(
            VALIDATOR.read_bytes()
        )
        (stack / "bin" / "credential-governance.json").write_bytes(
            CREDENTIAL_CATALOG.read_bytes()
        )
        catalog = json.loads(CREDENTIAL_CATALOG.read_text(encoding="utf-8"))
        entry = catalog["entries"][0]
        inventory = {
            "schema": "onion-sentinel-credential-inventory-v1",
            "generated_at": "2026-08-15T00:00:00Z",
            "required_ids": [entry["id"]],
            "records": [{
                "credential_id": entry["id"],
                "generation": 1,
                "state": "active",
                "created_at": "2026-08-14T00:00:00Z",
                "expires_at": "2099-08-14T00:00:00Z",
                "rotation_due_at": "2099-02-14T00:00:00Z",
                "storage_class": entry["storage_class"],
                "allowed_actions": entry["allowed_actions"],
                "predecessor_generation": None,
            }],
        }
        inventory_path = stack / "config" / "service-identity-inventory.json"
        inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
        os.chmod(inventory_path, 0o600)
        for name in ("alerts.sqlite3", "investigation-harness.sqlite3"):
            with closing(
                sqlite3.connect(stack / "alert_store_data" / name)
            ) as connection, connection:
                connection.execute("CREATE TABLE metadata (value TEXT)")
        return stack

    def test_stack_fixture_closes_database_connections(self):
        gc.collect()
        with tempfile.TemporaryDirectory() as directory:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", ResourceWarning)
                self.make_stack(Path(directory))
                gc.collect()
        unclosed = [
            warning
            for warning in caught
            if "unclosed database" in str(warning.message)
        ]
        self.assertEqual(unclosed, [])

    def test_snapshot_is_bounded_secret_safe_and_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            stack = self.make_stack(Path(directory))
            before = {
                path: path.stat().st_mtime_ns
                for path in stack.rglob("*")
                if path.is_file()
            }
            with mock.patch.object(READINESS, "check_services", return_value={
                "component": "services", "state": "ready", "reason_code": "test", "duration_ms": 0
            }), mock.patch.object(READINESS, "check_supervision", return_value={
                "component": "supervision", "state": "ready", "reason_code": "test", "duration_ms": 0
            }):
                value = READINESS.snapshot(stack, network=False, minimum_free_bytes=0)
            serialized = json.dumps(value)
            self.assertTrue(value["ok"])
            self.assertNotIn("SECRET", serialized)
            self.assertNotIn("not-read", serialized)
            self.assertEqual(value["components"][-1]["state"], "unverified")
            self.assertEqual(
                before,
                {path: path.stat().st_mtime_ns for path in before},
            )

    def test_unsafe_secret_config_fails_without_disclosing_path_or_value(self):
        with tempfile.TemporaryDirectory() as directory:
            stack = self.make_stack(Path(directory))
            os.chmod(stack / "config" / "incident-evidence.json", 0o644)
            value = READINESS.check_configuration(stack)
            self.assertEqual(value["state"], "failed")
            self.assertEqual(value["reason_code"], "permissions_too_open")
            self.assertNotIn(str(stack), json.dumps(value))

    def test_relay_network_check_is_only_a_bounded_tcp_connect(self):
        with tempfile.TemporaryDirectory() as directory:
            stack = self.make_stack(Path(directory))
            connection = mock.MagicMock()
            connection.__enter__.return_value = connection
            with mock.patch.object(READINESS.socket, "create_connection", return_value=connection) as connect:
                value = READINESS.check_relay(stack, True)
            self.assertEqual(value["state"], "ready")
            connect.assert_called_once_with(("127.0.0.1", 22), timeout=2.0)

    def test_database_check_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.sqlite3"
            with closing(sqlite3.connect(source)):
                pass
            link = root / "link.sqlite3"
            link.symlink_to(source)
            value = READINESS.check_database(link, "database")
            self.assertEqual(value["state"], "failed")
            self.assertEqual(value["reason_code"], "unsafe_file_type")

    def test_database_check_does_not_apply_config_file_size_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "large.sqlite3"
            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute("CREATE TABLE payload (value BLOB)")
                connection.execute(
                    "INSERT INTO payload VALUES (zeroblob(?))",
                    (READINESS.MAX_CONFIG_BYTES + 1,),
                )
            value = READINESS.check_database(database, "database")
            self.assertEqual(value["state"], "ready")

    def test_ollama_assignment_validates_api_endpoint_not_local_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            stack = self.make_stack(Path(directory))
            settings_path = stack / "config" / "ai_model_settings.json"
            settings = json.loads(settings_path.read_text())
            settings["agent_models"] = {
                "incident-responder": "ollama:example-model",
            }
            settings["ollama_url"] = "http://127.0.0.1:11434"
            settings_path.write_text(json.dumps(settings))
            with mock.patch.object(READINESS.shutil, "which", return_value=None):
                value = READINESS.check_providers(stack)
            self.assertEqual(value["state"], "ready")

    def test_supervision_surfaces_active_restart_quarantine(self):
        with tempfile.TemporaryDirectory() as directory:
            stack = self.make_stack(Path(directory))
            state = stack / "logs" / "onion-sentinel-web-restart-budget.json"
            state.write_text(json.dumps({
                "quarantined": True,
                "updated_at": READINESS.time.time(),
                "window_seconds": 900,
            }))
            os.chmod(state, 0o600)
            value = READINESS.check_supervision(stack)
            self.assertEqual(value["state"], "failed")
            self.assertEqual(value["reason_code"], "web_restart_quarantined")

    def test_supervision_detects_duplicate_workers(self):
        with tempfile.TemporaryDirectory() as directory:
            stack = self.make_stack(Path(directory))
            registered = mock.MagicMock(returncode=0, stdout="")
            duplicate = mock.MagicMock(returncode=0, stdout="41\n42\n")
            with mock.patch.object(
                READINESS.subprocess,
                "run",
                side_effect=[registered] * 6 + [duplicate],
            ):
                value = READINESS.check_supervision(stack)
            self.assertEqual(value["state"], "failed")
            self.assertEqual(value["reason_code"], "duplicate_ollama_workers")


if __name__ == "__main__":
    unittest.main()
