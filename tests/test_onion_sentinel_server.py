import importlib
from email.message import Message
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD_DIR))
server = importlib.import_module("onion_sentinel_server")


class OnionSentinelServerTests(unittest.TestCase):
    def test_server_release_reader_is_literal_private_and_duplicate_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env"
            env_path.write_text(
                "TOKEN=must-not-be-evaluated\n"
                "ONION_SENTINEL_RELEASE_ID=release-1234567\n",
                encoding="utf-8",
            )
            os.chmod(env_path, 0o600)
            self.assertEqual(
                server.current_runtime_release_id(
                    environ={},
                    env_path=env_path,
                ),
                "release-1234567",
            )
            env_path.write_text(
                "ONION_SENTINEL_RELEASE_ID=release-1234567\n"
                "ONION_SENTINEL_RELEASE_ID=release-7654321\n",
                encoding="utf-8",
            )
            self.assertEqual(
                server.current_runtime_release_id(
                    environ={},
                    env_path=env_path,
                ),
                "",
            )
            os.chmod(env_path, 0o640)
            self.assertEqual(
                server.current_runtime_release_id(
                    environ={},
                    env_path=env_path,
                ),
                "",
            )

    def test_login_rendering_escapes_message_and_form_token(self):
        with mock.patch.object(
            server.runtime,
            "ensure_admin_token",
            return_value='token"><script>bad()</script>',
        ):
            rendered = server.render_login(
                '<img src=x onerror="bad()">',
                error=True,
            ).decode("utf-8")
        self.assertNotIn("<img src=x", rendered)
        self.assertNotIn("<script>bad()", rendered)
        self.assertIn("&lt;img", rendered)
        self.assertIn("token&quot;&gt;&lt;script&gt;", rendered)
        self.assertIn('<p class="error">', rendered)

    def test_controlled_readiness_requires_exact_downstream_identity(self):
        healthy = {
            "service": "onion-sentinel-alert-store",
            "controlled_evaluation": True,
            "runtime_mode": "controlled-evaluation",
            "release_id": server.RUNTIME_RELEASE_ID,
            "listen_host": "127.0.0.1",
            "listen_port": 8787,
            "accepting_requests": True,
        }
        with (
            mock.patch.object(
                server.runtime,
                "SOC_ALERT_STORE_API_URL",
                "http://127.0.0.1:8787",
            ),
            mock.patch.object(
                server.runtime,
                "alert_store_get_json",
                return_value=healthy,
            ),
        ):
            ready, projection = server.controlled_alert_store_readiness()
        self.assertTrue(ready)
        self.assertEqual(projection["status"], "ready")

        healthy["release_id"] = "different-release"
        with mock.patch.object(
            server.runtime,
            "alert_store_get_json",
            return_value=healthy,
        ):
            ready, projection = server.controlled_alert_store_readiness()
        self.assertFalse(ready)
        self.assertEqual(projection["status"], "identity_mismatch")

    def test_controlled_readiness_projects_mismatch_fields_without_widening(self):
        health = {
            "service": None,
            "controlled_evaluation": 1,
            "runtime_mode": 42,
            "release_id": False,
            "listen_host": None,
            "listen_port": "8787",
            "accepting_requests": 1,
            "credential": "must-not-project",
        }
        with (
            mock.patch.object(
                server.runtime,
                "SOC_ALERT_STORE_API_URL",
                "http://127.0.0.1:8787/private?token=not-projected",
            ),
            mock.patch.object(
                server.runtime,
                "alert_store_get_json",
                return_value=health,
            ) as request,
        ):
            ready, projection = server.controlled_alert_store_readiness()

        self.assertFalse(ready)
        self.assertEqual(
            projection,
            {
                "status": "identity_mismatch",
                "service": "",
                "controlled_evaluation": False,
                "runtime_mode": "42",
                "release_id": "",
                "listen_host": "",
                "listen_port": "8787",
                "accepting_requests": False,
            },
        )
        request.assert_called_once_with("/health", timeout=1.0)
        self.assertNotIn("credential", projection)

    def test_controlled_readiness_fails_closed_with_bounded_unavailable_projection(self):
        with (
            mock.patch.object(
                server.runtime,
                "SOC_ALERT_STORE_API_URL",
                "http://127.0.0.1:8787",
            ),
            mock.patch.object(
                server.runtime,
                "alert_store_get_json",
                side_effect=RuntimeError("credential-bearing diagnostic"),
            ),
        ):
            self.assertEqual(
                server.controlled_alert_store_readiness(),
                (False, {"status": "unavailable"}),
            )

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
        self.assertTrue(server.is_soc_get_api("/api/admin/session-status"))
        self.assertTrue(
            server.is_soc_get_api("/api/ac-hunter/deep-review")
        )
        self.assertTrue(server.is_soc_get_api("/api/asset-inventory"))
        self.assertTrue(
            server.is_soc_get_api("/api/cyber-threat-intel/program")
        )
        self.assertTrue(server.is_soc_get_api("/api/software-inventory"))
        self.assertTrue(server.is_soc_get_api("/api/soc-alerts"))
        self.assertTrue(server.is_soc_get_api("/api/soc-incidents"))
        self.assertTrue(server.is_soc_get_api("/api/soc-incidents/reanalysis-runs"))
        self.assertTrue(server.is_soc_get_api("/api/soc-incidents/ir-example/detail"))
        self.assertTrue(server.is_soc_get_api("/api/soc-incidents/ir-example/adjudications"))
        self.assertTrue(server.is_soc_get_api("/api/soc-alerts/example/detail"))
        self.assertTrue(server.is_soc_get_api("/api/soc-alerts/example/adjudications"))
        self.assertTrue(server.is_soc_get_api("/api/soc-settings/agent-memory"))
        self.assertFalse(server.is_soc_get_api("/api/reports"))
        self.assertFalse(server.is_soc_get_api("/api/resource-library/favorites"))
        self.assertFalse(server.is_soc_get_api("/api/admin/service-status"))

        self.assertTrue(server.is_soc_post_api("/api/soc-alerts/example/analyze"))
        self.assertTrue(
            server.is_soc_post_api("/api/ac-hunter/refresh")
        )
        self.assertTrue(server.is_soc_post_api("/api/soc-alerts/example/pcap"))
        self.assertTrue(server.is_soc_post_api("/api/soc-alerts/example/escalate"))
        self.assertTrue(server.is_soc_post_api("/api/soc-alerts/example/adjudicate"))
        self.assertTrue(server.is_soc_post_api("/api/soc-incidents/ir-example/adjudicate"))
        self.assertTrue(server.is_soc_post_api("/api/soc-incidents/ir-example/status"))
        self.assertTrue(server.is_soc_post_api("/api/soc-incidents/ir-example/reanalyze"))
        self.assertTrue(server.is_soc_post_api("/api/soc-incidents/reanalyze-all"))
        self.assertTrue(server.is_soc_post_api("/api/soc-settings/agent-model"))
        self.assertTrue(server.is_soc_post_api("/api/soc-settings/ai-model"))
        self.assertTrue(
            server.is_soc_post_api("/api/cyber-threat-intel/program")
        )
        self.assertTrue(server.is_soc_post_api("/api/assets/promote-dhcp"))
        self.assertTrue(server.is_soc_post_api("/api/assets/update"))
        self.assertTrue(server.is_soc_post_api("/api/assets/demote"))
        self.assertTrue(
            server.is_soc_post_api("/api/assets/approve-dhcp-ip-change")
        )
        self.assertFalse(server.is_soc_post_api("/api/resource-library/remove"))
        self.assertFalse(server.is_soc_post_api("/api/admin/start-service"))
        self.assertFalse(server.is_soc_post_api("/admin/action"))

    def test_cti_program_route_is_fixed_and_not_prefix_writable(self):
        route = "/api/cyber-threat-intel/program"
        self.assertTrue(server.is_soc_get_api(route))
        self.assertTrue(server.is_soc_post_api(route))
        for malformed in (
            "/api/cyber-threat-intel/program/",
            "/api/cyber-threat-intel/program/source-1",
            "/api/cyber-threat-intel/arbitrary",
        ):
            self.assertFalse(server.is_soc_get_api(malformed), malformed)
            self.assertFalse(server.is_soc_post_api(malformed), malformed)

    def test_dynamic_soc_routes_require_one_exact_resource_segment(self):
        allowed_get = (
            "/api/soc-alerts/0123456789ab",
            "/api/soc-alerts/0123456789ab/detail",
            "/api/soc-alerts/0123456789ab/adjudications",
            "/api/soc-incidents/ir-example/detail",
            "/api/soc-incidents/ir-example/adjudications",
        )
        allowed_post = (
            "/api/soc-alerts/0123456789ab/ack",
            "/api/soc-alerts/0123456789ab/analyze",
            "/api/soc-alerts/0123456789ab/pcap",
            "/api/soc-alerts/0123456789ab/escalate",
            "/api/soc-alerts/0123456789ab/adjudicate",
            "/api/soc-incidents/ir-example/adjudicate",
            "/api/soc-incidents/ir-example/status",
            "/api/soc-incidents/ir-example/reanalyze",
        )
        for route in allowed_get:
            self.assertTrue(server.is_soc_get_api(route), route)
        for route in allowed_post:
            self.assertTrue(server.is_soc_post_api(route), route)

        wrong_method = (
            "/api/soc-alerts/0123456789ab/adjudicate",
            "/api/soc-incidents/ir-example/status",
        )
        for route in wrong_method:
            self.assertFalse(server.is_soc_get_api(route), route)
        self.assertFalse(
            server.is_soc_post_api("/api/soc-alerts/0123456789ab/adjudications")
        )
        self.assertFalse(
            server.is_soc_post_api("/api/soc-incidents/ir-example/adjudications")
        )

        malformed = (
            "/api/soc-alerts//adjudicate",
            "/api/soc-alerts/0123456789ab/nested/adjudicate",
            "/api/soc-alerts/0123456789ab%2Fnested/adjudicate",
            "/api/soc-alerts/0123456789ab/unknown",
            "/api/soc-incidents//adjudications",
            "/api/soc-incidents/not-a-case/adjudications",
            "/api/soc-incidents/ir-example/nested/adjudications",
            "/api/soc-incidents/ir-example%2Fnested/adjudications",
        )
        for route in malformed:
            self.assertFalse(server.is_soc_get_api(route), route)
            self.assertFalse(server.is_soc_post_api(route), route)

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

        class Session:
            def __init__(self, authenticated):
                self.authenticated = authenticated

            def _admin_authenticated(self):
                return self.authenticated

        authorize_cti = (
            server.OnionSentinelHandler._cti_program_write_authorized
        )
        self.assertFalse(authorize_cti(Session(False)))
        self.assertTrue(authorize_cti(Session(True)))

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
        facade_copy = (
            'cp "$REPO_DIR/onion-sentinel-dashboard/'
            'onion_sentinel_server.py"'
        )
        for module in (
            "onion_sentinel_release.py",
            "onion_sentinel_application.py",
            "onion_sentinel_request_routes.py",
        ):
            module_copy = (
                'cp "$REPO_DIR/onion-sentinel-dashboard/' + module + '"'
            )
            self.assertIn(module_copy, installer)
            self.assertLess(
                installer.index(module_copy),
                installer.index(facade_copy),
            )
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
