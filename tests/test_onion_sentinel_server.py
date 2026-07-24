import importlib
from email.message import Message
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD_DIR))
server = importlib.import_module("onion_sentinel_server")


class OnionSentinelServerTests(unittest.TestCase):
    def test_mutating_soc_api_requires_same_origin_json(self):
        headers = Message()
        headers["Content-Type"] = "application/json; charset=utf-8"
        headers["Host"] = "10.77.7.225:8766"
        headers["Origin"] = "http://10.77.7.225:8766"
        self.assertTrue(server.is_same_origin_json_request(headers)[0])

        headers.replace_header("Origin", "http://attacker.invalid")
        valid, status, _message = server.is_same_origin_json_request(headers)
        self.assertFalse(valid)
        self.assertEqual(status, 403)

        headers.replace_header("Origin", "http://10.77.7.225:8766")
        headers.replace_header("Content-Type", "text/plain")
        valid, status, _message = server.is_same_origin_json_request(headers)
        self.assertFalse(valid)
        self.assertEqual(status, 415)

    def test_static_resolution_is_rooted_and_rejects_dot_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "index.html").write_text("ok", encoding="utf-8")
            (root / "assets").mkdir()
            (root / "assets" / "app.css").write_text("body{}", encoding="utf-8")

            self.assertEqual(server.resolve_dashboard_target(root, "/"), (root / "index.html").resolve())
            self.assertEqual(server.resolve_dashboard_target(root, "/assets/app.css"), (root / "assets" / "app.css").resolve())
            self.assertIsNone(server.resolve_dashboard_target(root, "/../outside"))
            self.assertIsNone(server.resolve_dashboard_target(root, "/.admin_token"))
            self.assertIsNone(server.resolve_dashboard_target(root, "/assets/.hidden"))

    def test_only_soc_api_routes_are_exposed(self):
        self.assertTrue(server.is_soc_get_api("/api/soc-alerts"))
        self.assertTrue(server.is_soc_get_api("/api/soc-incidents"))
        self.assertTrue(server.is_soc_get_api("/api/soc-incidents/ir-example/detail"))
        self.assertTrue(server.is_soc_get_api("/api/soc-alerts/example/detail"))
        self.assertTrue(server.is_soc_get_api("/api/soc-settings/agent-memory"))
        self.assertFalse(server.is_soc_get_api("/api/reports"))
        self.assertFalse(server.is_soc_get_api("/api/resource-library/favorites"))
        self.assertFalse(server.is_soc_get_api("/api/admin/service-status"))

        self.assertTrue(server.is_soc_post_api("/api/soc-alerts/example/analyze"))
        self.assertTrue(server.is_soc_post_api("/api/soc-alerts/example/pcap"))
        self.assertTrue(server.is_soc_post_api("/api/soc-alerts/example/escalate"))
        self.assertTrue(server.is_soc_post_api("/api/soc-settings/agent-model"))
        self.assertTrue(server.is_soc_post_api("/api/soc-settings/ai-model"))
        self.assertFalse(server.is_soc_post_api("/api/resource-library/remove"))
        self.assertFalse(server.is_soc_post_api("/api/admin/start-service"))
        self.assertFalse(server.is_soc_post_api("/admin/action"))

    def test_dedicated_settings_bypass_does_not_replace_admin_auth(self):
        class NoAdminSession:
            def _admin_authenticated(self):
                raise AssertionError("Dedicated Settings bypass checked an admin session")

        self.assertTrue(
            server.OnionSentinelHandler._soc_settings_write_authorized(NoAdminSession())
        )
        self.assertIs(
            server.OnionSentinelHandler._admin_authenticated,
            server.runtime.PortalHandler._admin_authenticated,
        )
        self.assertIs(
            server.OnionSentinelHandler._require_admin_auth,
            server.runtime.PortalHandler._require_admin_auth,
        )

    def test_all_role_primary_and_reviewer_prompt_routes_are_allowlisted(self):
        routes = {
            "/api/soc-settings/analyst-prompt",
            "/api/soc-settings/analyst-second-opinion-prompt",
            "/api/soc-settings/incident-responder-prompt",
            "/api/soc-settings/incident-responder-second-opinion-prompt",
            "/api/soc-settings/siem-engineer-prompt",
            "/api/soc-settings/siem-engineer-second-opinion-prompt",
            "/api/soc-settings/cyber-threat-intel-prompt",
            "/api/soc-settings/cyber-threat-intel-second-opinion-prompt",
            "/api/soc-settings/threat-hunter-prompt",
            "/api/soc-settings/threat-hunter-second-opinion-prompt",
        }
        self.assertEqual(set(server.runtime.SOC_SETTINGS_PROMPT_API_PATHS), routes)
        for route in routes:
            self.assertTrue(server.is_soc_get_api(route), route)
            self.assertTrue(server.is_soc_post_api(route), route)

        unknown = "/api/soc-settings/arbitrary-prompt"
        self.assertFalse(server.is_soc_get_api(unknown))
        self.assertFalse(server.is_soc_post_api(unknown))

    def test_runtime_paths_do_not_use_hermes_or_report_portal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "dashboard"
            server.configure_runtime_paths(root)
            paths = (
                server.runtime.SOC_ALERT_DASHBOARD_DIR,
                server.runtime.SOC_ALERT_DETAIL_DIR,
                server.runtime.SOC_ALERT_STATUS_FILE,
                server.runtime.SOC_ALERT_PCAP_WORKFLOW_STATE_FILE,
                server.runtime.ADMIN_STATE_DIR,
                server.runtime.ADMIN_PASSWORD_FILE,
            )
            for path in paths:
                rendered = str(path)
                self.assertNotIn("/.hermes/", rendered)
                self.assertNotIn("/report_portal/", rendered)

    def test_installer_keeps_dashboard_inside_n8n_runtime(self):
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text(encoding="utf-8")
        refresh = (ROOT / "n8n/bin/refresh-soc-dashboard.py").read_text(encoding="utf-8")
        self.assertIn('DASHBOARD_RUNTIME_DIR="${STACK_DIR}/onion-sentinel-dashboard"', installer)
        self.assertIn("dashboard_executive_metrics.py", installer)
        self.assertNotIn("HERMES_SCRIPT_DIR", installer)
        self.assertNotIn("HERMES_ASSET_DIR", installer)
        self.assertNotIn('PORTAL_DIR="${HOME}/report_portal"', installer)
        self.assertNotIn("sync-soc-alerts-portal.py", refresh)
        self.assertNotIn('HOME / ".hermes"', refresh)

    def test_dedicated_service_does_not_expose_hermes_routes(self):
        source = (DASHBOARD_DIR / "onion_sentinel_server.py").read_text(encoding="utf-8")
        for route in (
            "/api/reports",
            "/api/resource-library/",
            "/api/admin/service-status",
            "/admin/action",
        ):
            self.assertNotIn(f'"{route}"', source.split("class OnionSentinelHandler", 1)[0])

    def test_active_onion_sentinel_scripts_do_not_publish_into_hermes(self):
        checked = (
            ROOT / "n8n/bin/install-macstudio-stack.zsh",
            ROOT / "n8n/bin/refresh-soc-dashboard.py",
            ROOT / "onion-sentinel-dashboard/scripts/build_soc_alerts_dashboard.py",
        )
        forbidden = ("$HOME/.hermes", 'HOME / ".hermes"', "$HOME/report_portal", 'HOME / "report_portal"')
        for path in checked:
            content = path.read_text(encoding="utf-8")
            for token in forbidden:
                self.assertNotIn(token, content, f"{path.name} contains cross-project path {token}")

    def test_runtime_scripts_do_not_control_hermes_services(self):
        runtime_bin = ROOT / "n8n/bin"
        for path in runtime_bin.iterdir():
            if not path.is_file():
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
            self.assertNotIn("com.arron.reportportal", content, path.name)

    def test_operations_include_live_dashboard_boundary_check(self):
        verifier = (ROOT / "operations/verify-dashboard-isolation.zsh").read_text(encoding="utf-8")
        self.assertIn("http://127.0.0.1:8766/healthz", verifier)
        self.assertIn("http://127.0.0.1:8765/", verifier)
        self.assertIn("test ! -e \"$HOME/n8n-local/bin/sync-soc-alerts-portal.py\"", verifier)
        self.assertIn("test ! -e \"$HOME/.hermes/scripts/build_soc_alerts_dashboard.py\"", verifier)
        self.assertIn("test ! -e \"$HOME/report_portal/soc_alert_api.py\"", verifier)
        self.assertIn("test ! -e \"$HOME/report_portal/.soc_alert_status.json\"", verifier)
        self.assertIn("test ! -e \"$HOME/report_portal/library/Cybersecurity/SOC Alerts\"", verifier)
        self.assertIn("com\\.arron\\.reportportal", verifier)
        self.assertIn("http://127.0.0.1:8765/api/soc-alerts", verifier)
        self.assertIn("http://127.0.0.1:8765/api/system-health/beacons", verifier)
        self.assertIn(')\" = 404', verifier)


if __name__ == "__main__":
    unittest.main()
