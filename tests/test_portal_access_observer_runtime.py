from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_access_observer_runtime as runtime  # noqa: E402
from portal_request_routes import classify_post_route  # noqa: E402


def route(path: str):
    return classify_post_route(
        path,
        cti_program_path="/api/cyber-threat-intel/program",
        prompt_paths=set(),
    )


class PortalAccessObserverRuntimeTests(unittest.TestCase):
    def test_legacy_load_does_not_read_or_create_key_or_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            service = runtime.load_access_observer_runtime(
                environ={}, home=home
            )
            self.assertFalse(service.enabled)
            self.assertEqual(service.snapshot()["mode"], "legacy")
            self.assertEqual(list(home.rglob("*")), [])

    def test_observe_requires_owner_only_lowercase_hex_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            key_path = runtime.audit_signing_key_path(home)
            key_path.parent.mkdir(parents=True)
            key_path.write_text("ab" * 32 + "\n", encoding="ascii")
            os.chmod(key_path, 0o640)
            with self.assertRaises(runtime.AccessObserverConfigurationError):
                runtime.load_access_observer_runtime(
                    environ={runtime.ACCESS_MODE_ENV: "observe"}, home=home
                )
            os.chmod(key_path, 0o600)
            service = runtime.load_access_observer_runtime(
                environ={runtime.ACCESS_MODE_ENV: "observe"}, home=home
            )
            self.assertTrue(service.enabled)
            self.assertEqual(service.snapshot()["audit_event_count"], 0)

    def test_unqualified_enforcement_modes_fail_at_startup(self) -> None:
        for mode in ("admin-enforce", "rbac-enforce"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(
                    runtime.AccessObserverConfigurationError,
                    "not qualified",
                ):
                    runtime.load_access_observer_runtime(
                        environ={runtime.ACCESS_MODE_ENV: mode},
                        home=Path(tmp),
                    )

    def test_append_failure_is_telemetry_only_and_never_escapes_observe(self) -> None:
        failures: list[str] = []

        def fail_append(*_args, **_kwargs):
            raise RuntimeError("credential-bearing failure must not escape")

        service = runtime.AccessObserverRuntime(
            mode="observe",
            signing_key=b"k" * 32,
            ledger_path=Path("/not-used"),
            append_event=fail_append,
            failure_sink=failures.append,
        )
        observation = service.begin(
            route("/api/soc-settings/ai-model"),
            principal=None,
            same_origin_authorized=False,
            csrf_authorized=False,
            request_id="request-6",
        )
        self.assertFalse(
            service.finalize(
                observation,
                http_status=200,
                occurred_at="2026-08-15T05:00:03Z",
            )
        )
        self.assertEqual(failures, ["RuntimeError"])
        self.assertEqual(service.snapshot()["audit_failure_count"], 1)
        self.assertNotIn("credential-bearing", str(service.snapshot()))


if __name__ == "__main__":
    unittest.main()
