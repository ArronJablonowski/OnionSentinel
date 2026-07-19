import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n/bin/ensure-onion-sentinel-web.py"
SPEC = importlib.util.spec_from_file_location("web_guard", SCRIPT)
assert SPEC and SPEC.loader
WEB_GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WEB_GUARD)


class WebServiceGuardTests(unittest.TestCase):
    def test_classifies_only_expected_and_known_unsafe_commands(self):
        self.assertEqual(
            WEB_GUARD.command_kind(
                "/usr/bin/python3 /runtime/onion_sentinel_server.py --host 0.0.0.0 --port 8766",
                8766,
            ),
            "onion-sentinel",
        )
        self.assertEqual(
            WEB_GUARD.command_kind("/opt/homebrew/bin/python3 -m http.server 8766 --bind 0.0.0.0", 8766),
            "unsafe-simple-http",
        )
        self.assertEqual(WEB_GUARD.command_kind("python3 -m http.server 8765", 8766), "unknown")
        self.assertEqual(WEB_GUARD.command_kind("python3 unknown_server.py --port 8766", 8766), "unknown")

    @mock.patch.object(WEB_GUARD.urllib.request, "urlopen")
    def test_health_requires_onion_sentinel_service_identity(self, urlopen):
        response = mock.MagicMock()
        entered = response.__enter__.return_value
        entered.headers = {}
        entered.read.side_effect = [
            json.dumps({"ok": True, "service": "onion-sentinel"}).encode(),
            b"",
        ]
        urlopen.return_value = response
        self.assertEqual(WEB_GUARD.probe_health("http://127.0.0.1:8766/healthz"), (True, "onion-sentinel"))

        entered.read.side_effect = [json.dumps({"ok": True}).encode(), b""]
        self.assertEqual(
            WEB_GUARD.probe_health("http://127.0.0.1:8766/healthz"),
            (False, "identity-mismatch"),
        )

    @mock.patch.object(WEB_GUARD, "probe_health", return_value=(False, "identity-mismatch"))
    @mock.patch.object(WEB_GUARD, "process_details", return_value=(501, "python3 unknown.py --port 8766"))
    @mock.patch.object(WEB_GUARD, "listener_pids", return_value=[42])
    def test_recovery_refuses_unknown_listener(self, _pids, _details, _probe):
        with mock.patch.object(WEB_GUARD.os, "getuid", return_value=501):
            result = WEB_GUARD.recover(
                8766,
                WEB_GUARD.DEFAULT_LABEL,
                WEB_GUARD.DEFAULT_HEALTH_URL,
                Path("/tmp/unused.plist"),
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "refused")

    @mock.patch.object(WEB_GUARD, "ensure_started", return_value=False)
    @mock.patch.object(WEB_GUARD, "terminate_known_simple_server")
    @mock.patch.object(
        WEB_GUARD,
        "process_details",
        return_value=(501, "python3 -m http.server 8766 --bind 0.0.0.0"),
    )
    @mock.patch.object(WEB_GUARD, "listener_pids", return_value=[42])
    @mock.patch.object(
        WEB_GUARD,
        "probe_health",
        side_effect=[(False, "identity-mismatch"), (True, "onion-sentinel")],
    )
    def test_recovery_reclaims_exact_simple_server(
        self,
        _probe,
        _pids,
        _details,
        terminate,
        ensure_started,
    ):
        with mock.patch.object(WEB_GUARD.os, "getuid", return_value=501):
            result = WEB_GUARD.recover(
                8766,
                WEB_GUARD.DEFAULT_LABEL,
                WEB_GUARD.DEFAULT_HEALTH_URL,
                Path("/tmp/unused.plist"),
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "recovered")
        terminate.assert_called_once_with(42)
        ensure_started.assert_called_once_with(WEB_GUARD.DEFAULT_LABEL, Path("/tmp/unused.plist"))

    @mock.patch.object(WEB_GUARD.subprocess, "run")
    @mock.patch.object(WEB_GUARD, "validate_plist", return_value=Path("/safe/web.plist"))
    @mock.patch.object(WEB_GUARD, "service_registered", return_value=False)
    def test_missing_service_bootstraps_allowlisted_plist(self, _registered, _validate, run):
        run.return_value = mock.MagicMock(returncode=0)
        with mock.patch.object(WEB_GUARD.os, "getuid", return_value=501):
            self.assertTrue(WEB_GUARD.ensure_started(WEB_GUARD.DEFAULT_LABEL, Path("/safe/web.plist")))
        self.assertEqual(
            run.call_args_list[0].args[0],
            ["/bin/launchctl", "bootstrap", "gui/501", "/safe/web.plist"],
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["/bin/launchctl", "kickstart", "-k", "gui/501/com.arron.onion-sentinel.web"],
        )

    def test_recent_owned_maintenance_hold_is_honored(self):
        with tempfile.TemporaryDirectory() as directory:
            hold = Path(directory) / "hold"
            hold.write_text("maintenance\n")
            self.assertTrue(WEB_GUARD.maintenance_hold_active(hold))


if __name__ == "__main__":
    unittest.main()
