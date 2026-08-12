#!/usr/bin/env python3
"""Characterize the report-portal runtime namespace before decomposition."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
if str(DASHBOARD) not in sys.path:
    sys.path.insert(0, str(DASHBOARD))

import portal_runtime_config as CONFIG  # noqa: E402


def public_runtime_names(module: object) -> list[str]:
    return sorted(
        name
        for name in vars(module)
        if not (name.startswith("__") and name.endswith("__"))
    )


def runtime_metadata(module: object) -> list[tuple[object, ...]]:
    records: list[tuple[object, ...]] = []
    for name in public_runtime_names(module):
        value = getattr(module, name)
        records.append(
            (
                name,
                type(value).__module__,
                type(value).__qualname__,
                getattr(value, "__module__", None),
                getattr(value, "__qualname__", None),
            )
        )
    return records


class PortalRuntimeConfigFacadeTests(unittest.TestCase):
    def test_runtime_config_namespace_and_object_metadata_are_stable(self) -> None:
        names = public_runtime_names(CONFIG)
        self.assertEqual(len(names), 545)
        self.assertEqual(
            hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest(),
            "571cef99416096846aa74f1ad45ea87c40cbf7013e001d14c83a8ae131a61a60",
        )
        expected_metadata = {
            (3, 9): "9de3eaf4c9c102c9d58773972d85184eb72a3c0f80560d59e4850c02d2640e82",
            (3, 14): "ec14c7324e5748eeb0f976d7f9e30b475487087a8c138896582781d319acf99f",
        }
        serialized = json.dumps(
            runtime_metadata(CONFIG), separators=(",", ":")
        ).encode("utf-8")
        self.assertEqual(
            hashlib.sha256(serialized).hexdigest(),
            expected_metadata[sys.version_info[:2]],
        )
        self.assertIsNone(getattr(CONFIG, "__all__", None))
        self.assertEqual(CONFIG.CronJobSummary.__module__, "portal_runtime_config")

    def test_imported_aliases_retain_their_defining_objects(self) -> None:
        import portal_admin_action_state
        import portal_ai_model_policy
        import portal_incident_report_renderer
        import portal_soc_group_query
        import portal_soc_pcap_request_policy

        expected = {
            "claim_action_lock": portal_admin_action_state.claim_action_lock,
            "default_soc_ai_settings": portal_ai_model_policy.default_soc_ai_settings,
            "render_incident_response_report": (
                portal_incident_report_renderer.render_incident_response_report
            ),
            "SocGroupQueryRequest": portal_soc_group_query.SocGroupQueryRequest,
            "normalize_pcap_request_policy": (
                portal_soc_pcap_request_policy.normalize_pcap_request
            ),
        }
        for name, value in expected.items():
            with self.subTest(name=name):
                self.assertIs(getattr(CONFIG, name), value)

    def test_report_portal_namespace_and_mutable_singletons_are_stable(self) -> None:
        import report_portal as portal

        names = public_runtime_names(portal)
        self.assertEqual(len(names), 936)
        self.assertEqual(
            hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest(),
            "8038fb11f94b3e6766223bbd94c4ae972730f3e026ae05273669c3d903b7f88e",
        )
        for name in (
            "ADMIN_ACTIONS",
            "ADMIN_COMMAND_ENV",
            "ASSET_INVENTORY_CACHE",
            "ASSET_INVENTORY_CACHE_LOCK",
            "SOC_ALERT_ARTIFACT_CACHE",
            "SOC_ALERT_DB_WRITE_LOCK",
            "SOC_ALERT_EVENTS_CACHE",
            "SOC_ALERT_LLM_ANALYSIS_LOG_INDEX",
            "SOC_ALERT_RESPONSE_CACHE",
            "CronJobSummary",
        ):
            with self.subTest(name=name):
                self.assertIs(getattr(portal, name), getattr(CONFIG, name))

    def test_environment_derived_policy_values_are_preserved(self) -> None:
        command = (
            "import json,sys;sys.path.insert(0,sys.argv[1]);"
            "import portal_runtime_config as c;"
            "print(json.dumps({"
            "'api':c.SOC_ALERT_STORE_API_URL,"
            "'direct':c.SOC_ALERT_STORE_DIRECT_WRITE_ALLOWED,"
            "'asset_read':c.ASSET_DATABASE_READ_ENABLED,"
            "'software_read':c.SOFTWARE_DATABASE_READ_ENABLED,"
            "'admin_write':c.ASSET_INVENTORY_ADMIN_WRITE_REQUIRED,"
            "'token':c.SOC_ALERT_STORE_EVALUATION_TOKEN"
            "},sort_keys=True))"
        )
        environment = {
            **os.environ,
            "PYTHONPATH": str(DASHBOARD),
            "SOC_ALERT_STORE_API_URL": "http://127.0.0.1:9999/",
            "SOC_ALERT_STORE_DIRECT_WRITE_ALLOWED": "1",
            "ASSET_DATABASE_READ_ENABLED": "true",
            "SOFTWARE_DATABASE_READ_ENABLED": "no",
            "ASSET_INVENTORY_ADMIN_WRITE_REQUIRED": "yes",
            "ONION_SENTINEL_EVALUATION_TOKEN": "characterization-only-token",
        }
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", command, str(DASHBOARD)],
            env=environment,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout),
            {
                "admin_write": True,
                "api": "http://127.0.0.1:9999",
                "asset_read": True,
                "direct": True,
                "software_read": False,
                "token": "characterization-only-token",
            },
        )


if __name__ == "__main__":
    unittest.main()
