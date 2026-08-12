#!/usr/bin/env python3
"""Characterization for the live OSQuery client compatibility boundary."""
from __future__ import annotations

import hashlib
import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

import live_osquery_client as CLIENT  # noqa: E402


class LiveOsqueryClientArchitectureTests(unittest.TestCase):
    def test_facade_compatibility_surface_and_signatures_are_stable(self) -> None:
        names = sorted(
            name for name in vars(CLIENT)
            if not name.startswith("__")
        )
        self.assertEqual(len(names), 49)
        self.assertEqual(
            hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest(),
            "8b51de574f6612e0b6bb1ab407a92aaeccf87200e217285fe0d16ce11238df0e",
        )
        expected = {
            "LiveOsqueryClientError": (
                "(message: 'str', *, reason_code: 'str' = "
                "'configuration_error') -> 'None'"
            ),
            "_atomic_write_json": (
                "(path: 'Path', value: 'dict[str, Any]') -> 'None'"
            ),
            "_bounded_int": (
                "(value: 'Any', *, label: 'str', default: 'int', "
                "minimum: 'int', maximum: 'int') -> 'int'"
            ),
            "_open_locked_case_manifest": "(case_dir: 'Path') -> 'int'",
            "_persist_live_osquery_artifact": (
                "(*, artifact_dir: 'Path', case_id: 'str', "
                "request_payload: 'dict[str, Any]', artifact: 'dict[str, Any]', "
                "maximum_batches: 'int') -> 'Path'"
            ),
            "_read_json": (
                "(path: 'Path', maximum: 'int' = 65536) -> 'dict[str, Any]'"
            ),
            "_run_restricted_transport": (
                "(command: 'list[str]', *, stdin_text: 'str', "
                "timeout_seconds: 'float')"
            ),
            "capability_descriptor": (
                "(config: 'dict[str, Any]') -> 'dict[str, Any]'"
            ),
            "collect_live_osquery": (
                "(*, case_id: 'str', requests: 'Any', config: 'dict[str, Any]', "
                "persist: 'bool' = True, approval_scope: 'str' = 'harness') "
                "-> 'dict[str, Any]'"
            ),
            "harness_operator_approved": (
                "(config: 'dict[str, Any] | None', target_alias: 'Any', *, "
                "now: 'dt.datetime | None' = None) -> 'bool'"
            ),
            "load_live_osquery_config": (
                "(path: 'Path' = "
                "PosixPath('/Users/aj_lobster/n8n-local/config/live-osquery.json')) "
                "-> 'dict[str, Any]'"
            ),
            "project_now": "() -> 'str'",
            "scheduled_inventory_approved": (
                "(config: 'dict[str, Any] | None', target_alias: 'Any') -> 'bool'"
            ),
        }
        self.assertEqual(
            {
                name: str(inspect.signature(getattr(CLIENT, name)))
                for name in expected
            },
            expected,
        )

    def test_client_imports_from_its_isolated_flat_bin_dependency_unit(self) -> None:
        sources = [
            BIN_DIR / name
            for name in (
                "bounded_process_policy.py",
                "bounded_process_io.py",
                "bounded_process_observation.py",
                "bounded_process_termination.py",
                "bounded_process_runtime.py",
                "bounded_process.py",
                "live_osquery_contract.py",
                "live_osquery_client_primitives.py",
                "live_osquery_client_config.py",
                "live_osquery_client_policy.py",
                "live_osquery_client_transport.py",
                "live_osquery_client_custody.py",
                "live_osquery_client.py",
            )
        ]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            for source in sources:
                (target / source.name).write_bytes(source.read_bytes())
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    (
                        "import sys; sys.path.insert(0, sys.argv[1]); "
                        "import live_osquery_client"
                    ),
                    directory,
                ],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_collect_order_request_transport_validation_and_custody_are_exact(self) -> None:
        request = {
            "target_alias": "endpoint-a",
            "query": "SELECT hostname FROM system_info LIMIT 1;",
            "purpose": "verify endpoint identity",
        }
        normalized = CLIENT.normalize_requests(
            [request],
            allowed_aliases=["endpoint-a"],
        )
        raw_artifact = {
            "schema": "onion-sentinel-live-osquery-v1",
            "case_id": "case-characterized",
            "generated_at": "2026-08-12T08:00:00Z",
            "read_only": True,
            "complete": True,
            "results": [{
                "target_alias": "endpoint-a",
                "query": request["query"],
                "purpose": request["purpose"],
                "status": "ok",
                "rows": [{"hostname": "endpoint-a"}],
                "total_rows": 1,
                "truncated": False,
                "duration_ms": 10,
                "error": "",
            }],
        }
        expected_artifact = CLIENT.validate_result_artifact(
            raw_artifact,
            expected_requests=normalized,
        )
        config = {
            "enabled": True,
            "allowed_target_aliases": ["endpoint-a"],
            "scheduled_inventory_approval": {
                "approved": True,
                "target_aliases": ["endpoint-a"],
            },
            "relay_host": "relay.invalid",
            "relay_user": "broker",
            "identity_file": Path("/private/runtime/id_ed25519"),
            "known_hosts": Path("/private/runtime/known_hosts"),
            "connect_timeout_seconds": 7,
            "timeout_seconds": 31,
            "port": 2222,
            "artifact_dir": Path("/private/runtime/artifacts"),
            "max_saved_batches_per_case": 3,
        }
        completed = SimpleNamespace(
            returncode=0,
            stdout=json.dumps(raw_artifact),
            stderr="",
        )
        calls = []

        def approve(candidate_config, alias):
            calls.append(("approve", candidate_config, alias))
            return True

        def run(command, **kwargs):
            calls.append(("transport", command, kwargs))
            return completed

        def validate(candidate, *, expected_requests):
            calls.append(("validate", candidate, expected_requests))
            return expected_artifact

        def persist(**kwargs):
            calls.append(("persist", kwargs))
            return Path("/private/runtime/artifact.json")

        with (
            mock.patch.object(
                CLIENT,
                "scheduled_inventory_approved",
                side_effect=approve,
            ),
            mock.patch.object(CLIENT, "run_bounded_command", side_effect=run),
            mock.patch.object(
                CLIENT,
                "validate_result_artifact",
                side_effect=validate,
            ),
            mock.patch.object(
                CLIENT,
                "_persist_live_osquery_artifact",
                side_effect=persist,
            ),
        ):
            artifact = CLIENT.collect_live_osquery(
                case_id=" case-characterized ",
                requests=[request],
                config=config,
                persist=True,
                approval_scope="scheduled_inventory",
            )

        self.assertIs(artifact, expected_artifact)
        self.assertEqual(
            [call[0] for call in calls],
            ["approve", "transport", "validate", "persist"],
        )
        self.assertIs(calls[0][1], config)
        self.assertEqual(calls[0][2], "endpoint-a")
        self.assertEqual(
            calls[1][1],
            [
                "ssh", "-T",
                "-o", "BatchMode=yes",
                "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "UserKnownHostsFile=/private/runtime/known_hosts",
                "-o", "ConnectTimeout=7",
                "-o", "ServerAliveInterval=15",
                "-o", "ServerAliveCountMax=3",
                "-i", "/private/runtime/id_ed25519",
                "-p", "2222",
                "broker@relay.invalid",
            ],
        )
        payload = {
            "schema": "onion-sentinel-live-osquery-v1",
            "case_id": "case-characterized",
            "requests": normalized,
        }
        self.assertEqual(
            calls[1][2],
            {
                "stdin_text": CLIENT.bounded_json_bytes(payload).decode("ascii"),
                "timeout_seconds": 31.0,
                "max_stdout_bytes": CLIENT.MAX_RESPONSE_BYTES,
                "max_stderr_bytes": CLIENT.MAX_STDERR_BYTES,
            },
        )
        self.assertEqual(calls[2][1], raw_artifact)
        self.assertEqual(calls[2][2], normalized)
        self.assertEqual(
            calls[3][1],
            {
                "artifact_dir": config["artifact_dir"],
                "case_id": "case-characterized",
                "request_payload": payload,
                "artifact": expected_artifact,
                "maximum_batches": 3,
            },
        )


if __name__ == "__main__":
    unittest.main()
