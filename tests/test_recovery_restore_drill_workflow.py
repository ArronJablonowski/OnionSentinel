"""Characterization for recovery restore-drill orchestration."""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import datetime as dt
import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n" / "bin" / "run-recovery-restore-drill.py"
INSTALLER = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_module():
    spec = importlib.util.spec_from_file_location("recovery_restore_workflow", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


restore = load_module()
TEST_SCHEME = "openssl-aes-256-cbc-pbkdf2-sha256+hmac-sha256-etm-v1"
TEST_PBKDF2_ITERATIONS = 600_000


class FakeEncryption:
    descriptor = {
        "scheme": TEST_SCHEME,
        "pbkdf2_iterations": TEST_PBKDF2_ITERATIONS,
        "authenticated": True,
        "key_source": "injected",
        "key_id": "injected",
    }

    def __init__(self, events: list[str] | None = None):
        self.events = events

    def decrypt_file(
        self,
        source: Path,
        destination: Path,
        *,
        expected_plaintext_sha256: str,
    ) -> dict[str, object]:
        if self.events is not None:
            self.events.append(f"decrypt:{source.name}")
        payload = source.read_bytes()
        if not payload.startswith(b"encrypted:"):
            raise RuntimeError("fixture authentication failed")
        plaintext = payload.removeprefix(b"encrypted:")
        self.assert_digest(plaintext, expected_plaintext_sha256)
        destination.write_bytes(plaintext)
        destination.chmod(0o600)
        return {
            "scheme": TEST_SCHEME,
            "plaintext_bytes": len(plaintext),
            "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        }

    @staticmethod
    def assert_digest(payload: bytes, expected: str) -> None:
        if hashlib.sha256(payload).hexdigest() != expected:
            raise RuntimeError("fixture plaintext digest mismatch")


class FixedDateTime(dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 8, 12, 1, 2, 3, 456789, tzinfo=dt.timezone.utc)

    def astimezone(self, tz=None):
        return self


class RecoveryRestoreWorkflowCharacterization(unittest.TestCase):
    def test_installer_deploys_recovery_credential_boundary_modules(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        for module in ("recovery_encryption.py", "recovery_bundle.py"):
            self.assertIn(
                f'cp "$REPO_DIR/n8n/bin/{module}" '
                f'"$STACK_DIR/bin/{module}"',
                installer,
            )

    def test_public_surface_and_target_signatures_are_exact(self) -> None:
        names = sorted(name for name in dir(restore) if not name.startswith("__"))
        encoded = json.dumps(names, separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(
            (len(names), hashlib.sha256(encoded).hexdigest()),
            (32, "be09d7f6457b0c26479a1aeabda535eb4c75d0cd3a701b7d3601bf91d7551a87"),
        )
        self.assertEqual(str(inspect.signature(restore.verify_bundle)), "(bundle: 'Path') -> 'dict[str, object]'")
        self.assertEqual(
            str(inspect.signature(restore.decrypt_bundle_files)),
            "(bundle: 'Path', manifest: 'dict[str, object]', destination: 'Path', encryption: 'RecoveryEncryption') -> 'dict[str, Path]'",
        )
        self.assertEqual(
            str(inspect.signature(restore.validate_harness_sqlite)),
            "(source: 'Path', temp_dir: 'Path') -> 'dict[str, object]'",
        )
        self.assertEqual(
            str(inspect.signature(restore.restore_postgres)),
            "(docker: 'str', dump: 'Path', *, source_container: 'str' = 'n8n-postgres', schema_kind: 'str' = 'n8n') -> 'dict[str, object]'",
        )
        self.assertEqual(str(inspect.signature(restore.main)), "() -> 'int'")

    def bundle(self, root: Path, *, extra_files: dict[str, bytes] | None = None) -> tuple[Path, dict]:
        bundle = root / "recovery-20260812T010203Z"
        bundle.mkdir(mode=0o700)
        plaintexts = {
            "alerts.sqlite3": b"alerts",
            "n8n-postgres.dump": b"postgres",
            "runtime-secrets.tar.gz": b"runtime",
            **(extra_files or {}),
        }
        payloads = {
            f"{name}.enc": b"encrypted:" + payload
            for name, payload in plaintexts.items()
        }
        for encrypted_name, payload in payloads.items():
            path = bundle / encrypted_name
            path.write_bytes(payload)
            path.chmod(0o600)
        manifest = {
            "encryption": FakeEncryption.descriptor,
            "files": {
                encrypted_name: {
                    "scheme": TEST_SCHEME,
                    "bytes": len(payloads[encrypted_name]),
                    "sha256": restore.sha256_file(bundle / encrypted_name),
                    "plaintext_name": encrypted_name.removesuffix(".enc"),
                    "plaintext_bytes": len(plaintexts[encrypted_name.removesuffix(".enc")]),
                    "plaintext_sha256": hashlib.sha256(
                        plaintexts[encrypted_name.removesuffix(".enc")]
                    ).hexdigest(),
                }
                for encrypted_name in payloads
            },
            "sqlite": {"investigation_harness": {"present": "investigation-harness.sqlite3" in plaintexts}},
            "postgres": {"alert_store_shadow": {"present": "alert-store-postgres.dump" in plaintexts}},
        }
        manifest_path = bundle / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        manifest_path.chmod(0o600)
        return bundle, manifest

    def test_bundle_validation_accepts_exact_required_and_optional_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle, manifest = self.bundle(
                Path(tmp),
                extra_files={
                    "investigation-harness.sqlite3": b"harness",
                    "alert-store-postgres.dump": b"shadow",
                },
            )
            self.assertEqual(restore.verify_bundle(bundle), manifest)

    def test_bundle_validation_rejects_unsafe_names_before_file_access(self) -> None:
        for name in ("/absolute", "nested/file", "unreviewed.dump"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                bundle, manifest = self.bundle(Path(tmp))
                manifest["files"] = {name: {"sha256": "0" * 64}}
                (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "^recovery bundle manifest contains an unsafe file$"):
                    restore.verify_bundle(bundle)

    def test_bundle_validation_preserves_hash_and_required_file_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle, manifest = self.bundle(Path(tmp))
            manifest["files"]["alerts.sqlite3.enc"]["sha256"] = "0" * 64
            (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "^bundle hash validation failed for alerts.sqlite3.enc$"):
                restore.verify_bundle(bundle)
        with tempfile.TemporaryDirectory() as tmp:
            bundle, manifest = self.bundle(Path(tmp))
            manifest["files"].pop("runtime-secrets.tar.gz.enc")
            (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "^recovery bundle is missing required files$"):
                restore.verify_bundle(bundle)

    def test_authenticated_payloads_decrypt_to_exact_reviewed_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle, manifest = self.bundle(
                root,
                extra_files={"investigation-harness.sqlite3": b"harness"},
            )
            destination = root / "plaintext"
            destination.mkdir(mode=0o700)
            events: list[str] = []
            paths = restore.decrypt_bundle_files(
                bundle,
                manifest,
                destination,
                FakeEncryption(events),
            )
            self.assertEqual(
                set(paths),
                {
                    "alerts.sqlite3",
                    "investigation-harness.sqlite3",
                    "n8n-postgres.dump",
                    "runtime-secrets.tar.gz",
                },
            )
            self.assertEqual(paths["alerts.sqlite3"].read_bytes(), b"alerts")
            self.assertEqual(
                events,
                [
                    "decrypt:alerts.sqlite3.enc",
                    "decrypt:investigation-harness.sqlite3.enc",
                    "decrypt:n8n-postgres.dump.enc",
                    "decrypt:runtime-secrets.tar.gz.enc",
                ],
            )

    def postgres_case(self, root: Path, *, schema_kind: str = "n8n"):
        dump = root / "database.dump"
        dump.write_bytes(b"dump")
        docker_calls: list[list[str]] = []

        def docker_output(_docker, args, **_kwargs):
            docker_calls.append(args)
            if args[0] == "inspect":
                return "postgres:fixture"
            if "to_regclass('onion_sentinel_queue.schema_version')" in args[-1]:
                return "1"
            if "shadow_durable_jobs" in args[-1]:
                return "4"
            if "information_schema.tables" in args[-1]:
                return "9"
            if "workflow_entity" in args[-1]:
                return "3"
            return ""

        def process_run(command, **_kwargs):
            return mock.Mock(returncode=0)

        return dump, docker_calls, docker_output, process_run

    def test_postgres_restore_preserves_isolation_commands_probes_and_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dump, docker_calls, docker_output, process_run = self.postgres_case(Path(tmp))
            with mock.patch.object(restore, "docker_output", side_effect=docker_output), mock.patch.object(
                restore.subprocess, "run", side_effect=process_run
            ) as run, mock.patch.object(restore.secrets, "token_hex", return_value="abcde12345"), mock.patch.object(
                restore.time, "monotonic", side_effect=[10, 11]
            ):
                result = restore.restore_postgres("/docker", dump)
        name = "onion-sentinel-restore-drill-abcde12345"
        self.assertEqual(
            docker_calls[:3],
            [
                ["inspect", "-f", "{{.Config.Image}}", "n8n-postgres"],
                [
                    "run", "--detach", "--rm", "--name", name, "--network", "none",
                    "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=4g",
                    "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "postgres:fixture",
                ],
                ["exec", name, "createdb", "-U", "postgres", "n8n_restore_drill"],
            ],
        )
        self.assertEqual(result, {"image": "postgres:fixture", "table_count": 9, "workflow_count": 3, "network": "none"})
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands[0], ["/docker", "exec", name, "pg_isready", "-U", "postgres"])
        self.assertEqual(commands[1][:5], ["/docker", "exec", "-i", name, "pg_restore"])
        self.assertEqual(commands[-1], ["/docker", "rm", "-f", name])
        self.assertEqual(run.call_args_list[1].kwargs["timeout"], 1800)

    def test_postgres_restore_preserves_shadow_schema_and_cleanup_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dump, docker_calls, docker_output, process_run = self.postgres_case(Path(tmp))
            with mock.patch.object(restore, "docker_output", side_effect=docker_output), mock.patch.object(
                restore.subprocess, "run", side_effect=process_run
            ) as run, mock.patch.object(restore.secrets, "token_hex", return_value="shadow"), mock.patch.object(
                restore.time, "monotonic", side_effect=[10, 11]
            ):
                result = restore.restore_postgres(
                    "/docker", dump, source_container="shadow-source", schema_kind="alert-store-shadow"
                )
        self.assertEqual(result, {"image": "postgres:fixture", "schema_version_rows": 1, "durable_job_rows": 4, "network": "none"})
        self.assertEqual(docker_calls[0][-1], "shadow-source")
        self.assertEqual(run.call_args_list[-1].args[0], ["/docker", "rm", "-f", "onion-sentinel-restore-drill-shadow"])

        with tempfile.TemporaryDirectory() as tmp:
            dump = Path(tmp) / "database.dump"
            dump.write_bytes(b"dump")
            def fail_restore(command, **_kwargs):
                if "pg_restore" in command:
                    raise subprocess.CalledProcessError(1, command)
                return mock.Mock(returncode=0)
            with mock.patch.object(restore, "docker_output", return_value="postgres:fixture"), mock.patch.object(
                restore.subprocess, "run", side_effect=fail_restore
            ) as run, mock.patch.object(restore.secrets, "token_hex", return_value="failure"), mock.patch.object(
                restore.time, "monotonic", side_effect=[10, 11]
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    restore.restore_postgres("/docker", dump)
            self.assertEqual(run.call_args_list[-1].args[0], ["/docker", "rm", "-f", "onion-sentinel-restore-drill-failure"])

    def test_main_preserves_success_order_report_contract_and_owner_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "recovery-20260812T010203Z"
            bundle.mkdir()
            args = argparse.Namespace(stack_dir=root, bundle=bundle, docker="/docker")
            manifest = {
                "alert_rows": 2,
                "harness_runs": 7,
                "encryption": FakeEncryption.descriptor,
            }
            events: list[str] = []
            stdout = io.StringIO()
            with mock.patch.object(argparse.ArgumentParser, "parse_args", return_value=args), mock.patch.object(
                restore, "verify_bundle", side_effect=lambda _path: events.append("verify") or manifest
            ), mock.patch.object(
                restore.RecoveryEncryption,
                "from_keychain",
                side_effect=lambda **_kwargs: events.append("keychain") or FakeEncryption(),
            ), mock.patch.object(
                restore,
                "decrypt_bundle_files",
                side_effect=lambda *_args: events.append("decrypt") or {
                    "alerts.sqlite3": bundle / "alerts.sqlite3",
                    "n8n-postgres.dump": bundle / "n8n-postgres.dump",
                    "runtime-secrets.tar.gz": bundle / "runtime-secrets.tar.gz",
                },
            ), mock.patch.object(
                restore, "validate_sqlite", side_effect=lambda *_args: events.append("sqlite") or {"alert_rows": 2}
            ), mock.patch.object(
                restore, "validate_runtime_archive", side_effect=lambda _path: events.append("archive") or {"member_count": 2}
            ), mock.patch.object(
                restore, "restore_postgres", side_effect=lambda *_args, **_kwargs: events.append("postgres") or {"network": "none"}
            ) as postgres, mock.patch.object(restore.dt, "datetime", FixedDateTime), mock.patch.object(
                restore.time, "monotonic", side_effect=[10, 12.345]
            ), redirect_stdout(stdout):
                code = restore.main()
            output = root / "logs/restore-drills/restore-drill-20260812T010203+0000.json"
            report = json.loads(output.read_text())
            self.assertEqual(code, 0)
            self.assertEqual(events, ["verify", "keychain", "decrypt", "sqlite", "archive", "postgres"])
            self.assertEqual(postgres.call_count, 1)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(
                report,
                {
                    "started_at": "2026-08-12  01:02:03+00:00",
                    "completed_at": "2026-08-12  01:02:03+00:00",
                    "bundle": bundle.name,
                    "status": "passed",
                    "sqlite": {"alert_rows": 2},
                    "investigation_harness": {"present": False},
                    "runtime_archive": {"member_count": 2},
                    "postgres": {"network": "none"},
                    "alert_store_postgres_shadow": {"present": False},
                    "manifest_alert_rows": 2,
                    "encryption": FakeEncryption.descriptor,
                    "runtime_seconds": 2.345,
                },
            )
            printed = json.loads(stdout.getvalue())
            self.assertEqual(printed, {"ok": True, "report": str(output), **report})

    def test_main_failure_still_publishes_bounded_failed_report_and_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "bundle"
            args = argparse.Namespace(stack_dir=root, bundle=bundle, docker="/docker")
            stdout = io.StringIO()
            with mock.patch.object(argparse.ArgumentParser, "parse_args", return_value=args), mock.patch.object(
                restore, "verify_bundle", side_effect=RuntimeError("synthetic verification failure")
            ), mock.patch.object(restore.dt, "datetime", FixedDateTime), mock.patch.object(
                restore.time, "monotonic", side_effect=[20, 20.25]
            ), redirect_stdout(stdout):
                code = restore.main()
            printed = json.loads(stdout.getvalue())
            self.assertEqual(code, 2)
            self.assertFalse(printed["ok"])
            self.assertEqual(printed["status"], "failed")
            self.assertEqual(printed["error"], "synthetic verification failure")
            self.assertEqual(printed["runtime_seconds"], 0.25)


if __name__ == "__main__":
    unittest.main()
