import importlib
import hashlib
import json
from email.message import Message
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD_DIR))
server = importlib.import_module("onion_sentinel_server")
observer_runtime_module = importlib.import_module(
    "portal_access_observer_runtime"
)
principal_module = importlib.import_module("portal_session_principal")


class OnionSentinelServerTests(unittest.TestCase):
    def test_post_starts_observation_before_preserving_existing_dispatch(self):
        handler = object.__new__(server.OnionSentinelHandler)
        handler.path = "/api/soc-settings/ai-model?source=settings"
        events = []
        access_runtime = SimpleNamespace(
            begin=lambda value, path, **kwargs: events.append(
                ("begin", value is handler, path, kwargs)
            ) or SimpleNamespace(allowed=True)
        )
        with (
            mock.patch.object(server, "ACCESS_RUNTIME", access_runtime),
            mock.patch.object(
                server._request_routes,
                "do_post",
                side_effect=lambda value, context: events.append(
                    ("dispatch", value is handler, context is server)
                ) or "dispatched",
            ),
        ):
            result = server.OnionSentinelHandler.do_POST(handler)
        self.assertEqual(result, "dispatched")
        self.assertEqual(
            events,
            [
                (
                    "begin",
                    True,
                    "/api/soc-settings/ai-model",
                    {"controlled_evaluation": False},
                ),
                ("dispatch", True, True),
            ],
        )

    def test_post_enforcement_denial_stops_before_existing_dispatch(self):
        handler = object.__new__(server.OnionSentinelHandler)
        handler.path = "/api/soc-settings/ai-model"
        admission = SimpleNamespace(
            allowed=False,
            status=401,
            reason="unauthenticated",
            json_request=True,
        )
        access_runtime = SimpleNamespace(begin=mock.Mock(return_value=admission))
        with (
            mock.patch.object(server, "ACCESS_RUNTIME", access_runtime),
            mock.patch.object(
                server._request_routes,
                "send_access_denial",
                return_value="denied",
                create=True,
            ) as deny,
            mock.patch.object(server._request_routes, "do_post") as dispatch,
        ):
            self.assertEqual(
                server.OnionSentinelHandler.do_POST(handler), "denied"
            )
        deny.assert_called_once_with(handler, server, admission)
        dispatch.assert_not_called()

    def test_response_finalizes_observation_once_without_changing_response(self):
        handler = object.__new__(server.OnionSentinelHandler)
        observation = object()
        handler._access_observation = observation
        observed_before_append = []
        observer_runtime = SimpleNamespace(
            finalize=mock.Mock(
                side_effect=lambda *_args, **_kwargs: observed_before_append.append(
                    handler._access_observation
                ) or False
            )
        )
        access_runtime = server._access_adapter.DedicatedAccessRuntime(
            runtime=server.runtime,
            observer=observer_runtime,
            sessions=SimpleNamespace(),
        )
        with (
            mock.patch.object(server, "ACCESS_RUNTIME", access_runtime),
            mock.patch.object(
                server.runtime,
                "now_iso_utc",
                return_value="2026-08-15T05:00:04Z",
            ),
            mock.patch.object(
                server.runtime.PortalHandler,
                "send_response",
                return_value="sent",
            ) as send,
        ):
            result = server.OnionSentinelHandler.send_response(handler, 202)
            server.OnionSentinelHandler.send_response(handler, 202)
        self.assertEqual(result, "sent")
        self.assertEqual(observed_before_append, [None])
        observer_runtime.finalize.assert_called_once_with(
            observation,
            http_status=202,
            occurred_at="2026-08-15T05:00:04Z",
        )
        self.assertEqual(send.call_count, 2)

    def test_begin_observation_classifies_dedicated_write_without_body_access(self):
        headers = Message()
        headers["Host"] = "10.77.7.225:8766"
        headers["Origin"] = "http://10.77.7.225:8766"
        handler = SimpleNamespace(
            headers=headers,
            application_request_id="request-7",
            _soc_review_origin_authorized=lambda: True,
        )
        observation = object()
        principal = object()
        observer_runtime = SimpleNamespace(
            enabled=True,
            begin=mock.Mock(return_value=observation),
        )
        session_runtime = SimpleNamespace(
            resolve_session=mock.Mock(
                return_value=SimpleNamespace(
                    principal=principal,
                    csrf_authorized=True,
                )
            )
        )
        handler._admin_session_id = lambda: "session-" + "s" * 36
        headers["X-Onion-Sentinel-CSRF"] = "csrf-" + "c" * 38
        access_runtime = server._access_adapter.DedicatedAccessRuntime(
            runtime=server.runtime,
            observer=observer_runtime,
            sessions=session_runtime,
        )
        admission = access_runtime.begin(
            handler,
            "/api/ac-hunter/refresh",
            controlled_evaluation=False,
        )
        self.assertIs(handler._access_observation, observation)
        called_route = observer_runtime.begin.call_args.args[0]
        self.assertTrue(called_route.accepted)
        self.assertEqual(called_route.path, "/api/ac-hunter/refresh")
        self.assertEqual(
            observer_runtime.begin.call_args.kwargs,
            {
                "principal": principal,
                "same_origin_authorized": True,
                "csrf_authorized": True,
                "request_id": "request-7",
            },
        )
        session_runtime.resolve_session.assert_called_once()
        self.assertTrue(admission.allowed)

    def test_admin_enforcement_denies_before_body_and_requires_audit_precommit(self):
        headers = Message()
        headers["Host"] = "10.77.7.225:8766"
        headers["Origin"] = "http://10.77.7.225:8766"
        headers["X-Onion-Sentinel-CSRF"] = "csrf-" + "c" * 38
        handler = SimpleNamespace(
            headers=headers,
            application_request_id="request-enforce-1",
            _soc_review_origin_authorized=lambda: True,
            _admin_session_id=lambda: "session-" + "s" * 36,
        )
        session = SimpleNamespace(
            principal=None,
            csrf_authorized=False,
            reason="session_missing",
        )
        denied_decision = SimpleNamespace(
            mode="admin-enforce",
            permission="settings.manage",
            allowed=False,
            enforced=True,
            would_authorize=False,
            reason="unauthenticated",
        )
        observer_runtime = SimpleNamespace(
            enabled=True,
            enforcing=True,
            begin=mock.Mock(
                return_value=SimpleNamespace(decision=denied_decision)
            ),
            precommit=mock.Mock(),
            record_boundary_failure=mock.Mock(),
        )
        session_runtime = SimpleNamespace(
            resolve_session=mock.Mock(return_value=session)
        )
        access_runtime = server._access_adapter.DedicatedAccessRuntime(
            runtime=server.runtime,
            observer=observer_runtime,
            sessions=session_runtime,
        )
        denied = access_runtime.begin(
            handler,
            "/api/soc-settings/ai-model",
            controlled_evaluation=False,
        )
        self.assertFalse(denied.allowed)
        self.assertEqual((denied.status, denied.reason), (401, "unauthenticated"))
        observer_runtime.precommit.assert_not_called()

        allowed_decision = SimpleNamespace(
            mode="admin-enforce",
            permission="settings.manage",
            allowed=True,
            enforced=True,
            would_authorize=True,
            reason="authorized",
        )
        session.principal = object()
        session.csrf_authorized = True
        session.reason = "authorized"
        observer_runtime.begin.return_value = SimpleNamespace(
            decision=allowed_decision
        )
        observer_runtime.precommit.return_value = False
        unavailable = access_runtime.begin(
            handler,
            "/api/soc-settings/ai-model",
            controlled_evaluation=False,
        )
        self.assertFalse(unavailable.allowed)
        self.assertEqual(
            (unavailable.status, unavailable.reason),
            (503, "audit_precommit_failed"),
        )

    def test_rbac_adapter_enforces_analyst_and_administrator_route_boundaries(self):
        appended = []
        observer = observer_runtime_module.AccessObserverRuntime(
            mode="rbac-enforce",
            signing_key=b"k" * 32,
            ledger_path=Path("/not-used"),
            append_event=lambda *_args, **kwargs: appended.append(kwargs) or {},
        )
        session = SimpleNamespace(
            principal=principal_module.HumanPrincipal(
                "human_session", "analyst-1", "analyst"
            ),
            csrf_authorized=True,
            reason="authorized",
        )
        sessions = SimpleNamespace(
            enabled=True,
            enforcing=True,
            resolve_session=mock.Mock(return_value=session),
        )
        access = server._access_adapter.DedicatedAccessRuntime(
            runtime=server.runtime,
            observer=observer,
            sessions=sessions,
        )
        headers = Message()
        headers["Host"] = "10.77.7.225:8766"
        headers["Origin"] = "http://10.77.7.225:8766"
        headers["X-Onion-Sentinel-CSRF"] = "csrf-" + "c" * 38
        handler = SimpleNamespace(
            headers=headers,
            application_request_id="request-rbac-2",
            _soc_review_origin_authorized=lambda: True,
            _admin_session_id=lambda: "session-" + "s" * 36,
        )
        analyst_write = access.begin(
            handler,
            "/api/soc-alerts/group/escalate",
            controlled_evaluation=False,
        )
        self.assertTrue(analyst_write.allowed)
        self.assertEqual(
            appended[0]["fields"]["reason_code"],
            "enforce_authorized_precommit",
        )
        admin_write = access.begin(
            handler,
            "/api/soc-settings/ai-model",
            controlled_evaluation=False,
        )
        self.assertFalse(admin_write.allowed)
        self.assertEqual(
            (admin_write.status, admin_write.reason),
            (403, "role_denied"),
        )

    def test_observe_login_and_logout_cookie_headers_preserve_legacy_default(self):
        disabled_sessions = SimpleNamespace(
            enabled=False,
            absolute_ttl_seconds=28_800,
        )
        enabled_sessions = SimpleNamespace(
            enabled=True,
            absolute_ttl_seconds=28_800,
        )
        with mock.patch.object(
            server.runtime,
            "admin_session_cookie_header",
            return_value="legacy-session-cookie",
        ):
            disabled = server._access_adapter.DedicatedAccessRuntime(
                runtime=server.runtime,
                observer=SimpleNamespace(),
                sessions=disabled_sessions,
            )
            enabled = server._access_adapter.DedicatedAccessRuntime(
                runtime=server.runtime,
                observer=SimpleNamespace(),
                sessions=enabled_sessions,
            )
            self.assertEqual(
                disabled.login_cookie_headers("legacy-id", None),
                "legacy-session-cookie",
            )
            self.assertEqual(
                enabled.login_cookie_headers("legacy-id", "csrf-" + "c" * 38),
                [
                    "legacy-session-cookie",
                    "onion_sentinel_csrf=csrf-" + "c" * 38
                    + "; Path=/; Max-Age=28800; SameSite=Strict",
                ],
            )
        with mock.patch.object(
            server.runtime,
            "expired_admin_session_cookie_header",
            return_value="expired-legacy-cookie",
        ):
            self.assertEqual(
                disabled.logout_cookie_headers(),
                "expired-legacy-cookie",
            )
            self.assertEqual(
                enabled.logout_cookie_headers(),
                [
                    "expired-legacy-cookie",
                    "onion_sentinel_csrf=; Path=/; Max-Age=0; SameSite=Strict",
                ],
            )

    def test_admin_enforcement_build_requires_strict_password_record(self):
        observer = SimpleNamespace(mode="admin-enforce", enforcing=True)
        sessions = object()
        with (
            mock.patch.object(
                server._access_adapter,
                "build_access_observer",
                return_value=observer,
            ),
            mock.patch.object(
                server._access_adapter,
                "build_human_session_runtime",
                return_value=sessions,
            ),
            mock.patch.object(
                server._access_adapter,
                "load_enforcement_admin_password_record",
                create=True,
                return_value={
                    "algorithm": "pbkdf2_sha256",
                    "iterations": 200_000,
                    "salt": "00" * 16,
                    "hash": "00" * 32,
                },
            ) as validate,
            mock.patch.object(
                server._access_adapter,
                "validate_admin_session_store",
                create=True,
            ) as validate_sessions,
        ):
            built = server._access_adapter.build_access_runtime(
                environ={},
                home=Path("/operator"),
                application_logger=object(),
                runtime=server.runtime,
            )
        self.assertIs(built.sessions, sessions)
        validate.assert_called_once_with(
            Path("/operator/n8n-local/config/onion-sentinel-admin-password.json")
        )
        validate_sessions.assert_called_once_with(
            Path("/operator/n8n-local/admin-state"),
            Path("/operator/n8n-local/admin-state/.admin_sessions.json"),
        )
        self.assertTrue(built.password_configured())

    def test_admin_enforcement_verifies_against_pinned_strict_record(self):
        salt = b"0123456789abcdef"
        password = "correct horse battery staple"
        record = {
            "algorithm": "pbkdf2_sha256",
            "iterations": 200_000,
            "salt": salt.hex(),
            "hash": hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt, 200_000
            ).hex(),
        }
        access = server._access_adapter.DedicatedAccessRuntime(
            runtime=SimpleNamespace(
                admin_password_configured=mock.Mock(side_effect=AssertionError),
                verify_admin_password=mock.Mock(side_effect=AssertionError),
            ),
            observer=SimpleNamespace(),
            sessions=SimpleNamespace(enforcing=True),
            password_record=record,
        )
        self.assertTrue(access.password_configured())
        self.assertTrue(access.verify_password(password))
        self.assertFalse(access.verify_password("wrong"))

    def test_enforcement_get_auth_never_trusts_only_the_legacy_cookie(self):
        handler = SimpleNamespace(
            headers=Message(),
            client_address=("127.0.0.1", 41414),
            _admin_authenticated=mock.Mock(return_value=True),
            _admin_session_id=lambda: "session-" + "s" * 36,
        )
        sessions = SimpleNamespace(
            enforcing=True,
            resolve_session=mock.Mock(return_value=SimpleNamespace(
                principal=None,
                csrf_authorized=False,
                reason="policy_generation_mismatch",
            )),
        )
        access = server._access_adapter.DedicatedAccessRuntime(
            runtime=server.runtime,
            observer=SimpleNamespace(),
            sessions=sessions,
            password_record={},
        )
        self.assertFalse(access.admin_authenticated(handler))
        handler._admin_authenticated.assert_not_called()

    def test_rbac_read_auth_accepts_every_human_role_but_admin_stays_narrow(self):
        handler = SimpleNamespace(
            _admin_session_id=lambda: "session-" + "s" * 36,
        )
        observation = SimpleNamespace(
            principal=principal_module.HumanPrincipal(
                "human_session", "viewer-1", "viewer"
            ),
            csrf_authorized=False,
            reason="authorized",
        )
        sessions = SimpleNamespace(
            mode="rbac-enforce",
            enforcing=True,
            resolve_read_session=mock.Mock(return_value=observation),
        )
        access = server._access_adapter.DedicatedAccessRuntime(
            runtime=server.runtime,
            observer=SimpleNamespace(),
            sessions=sessions,
            password_record={},
        )
        self.assertTrue(access.read_authenticated(handler))
        self.assertFalse(access.admin_authenticated(handler))
        self.assertEqual(sessions.resolve_read_session.call_count, 2)

    def test_admin_logout_bootstrap_sends_the_session_csrf_header(self):
        rendered = server.render_admin_status().decode("utf-8")
        self.assertIn("onion_sentinel_csrf=", rendered)
        self.assertIn("X-Onion-Sentinel-CSRF", rendered)
        self.assertIn("credentials:'same-origin'", rendered)
        self.assertIn("event.preventDefault()", rendered)

    def test_enforcement_modes_have_an_isolated_clean_startup_boundary(self):
        for mode in ("admin-enforce", "rbac-enforce"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                self._assert_isolated_enforcement_startup(Path(tmp), mode)

    def _assert_isolated_enforcement_startup(self, home: Path, mode: str):
        stack = home / "n8n-local"
        config = stack / "config"
        state = stack / "admin-state"
        config.mkdir(parents=True, mode=0o700)
        state.mkdir(mode=0o700)
        os.chmod(config, 0o700)
        os.chmod(state, 0o700)
        key = config / "onion-sentinel-admin-audit-signing.key"
        key.write_text("ab" * 32 + "\n", encoding="ascii")
        os.chmod(key, 0o600)
        password = config / "onion-sentinel-admin-password.json"
        password.write_text(
            json.dumps({
                "algorithm": "pbkdf2_sha256",
                "iterations": 200_000,
                "salt": "00" * 16,
                "hash": "00" * 32,
            }),
            encoding="utf-8",
        )
        os.chmod(password, 0o600)
        command = (
            "import sys; "
            f"sys.path.insert(0, {str(DASHBOARD_DIR)!r}); "
            "import onion_sentinel_server as server; "
            "assert server.ACCESS_RUNTIME.observer.enforcing; "
            "assert server.ACCESS_RUNTIME.session_required; "
            "assert server.ACCESS_RUNTIME.password_configured()"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", command],
            env={
                "HOME": str(home),
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "ONION_SENTINEL_ACCESS_MODE": mode,
                "ONION_SENTINEL_APPLICATION_LOG": str(
                    stack / "logs/application.jsonl"
                ),
            },
            cwd=home,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_begin_observation_boundary_failure_never_escapes_dispatch(self):
        handler = SimpleNamespace(
            headers=Message(),
            application_request_id="request-8",
            _soc_review_origin_authorized=mock.Mock(
                side_effect=RuntimeError("must not escape")
            ),
        )
        observer_runtime = SimpleNamespace(
            enabled=True,
            begin=mock.Mock(),
            record_boundary_failure=mock.Mock(),
        )
        accepted_route = SimpleNamespace(accepted=True)
        session_runtime = SimpleNamespace(resolve_session=mock.Mock())
        access_runtime = server._access_adapter.DedicatedAccessRuntime(
            runtime=server.runtime,
            observer=observer_runtime,
            sessions=session_runtime,
        )
        with (
            mock.patch.object(
                server.runtime,
                "classify_post_route",
                return_value=accepted_route,
            ),
        ):
            admission = access_runtime.begin(
                handler,
                "/api/soc-settings/ai-model",
                controlled_evaluation=False,
            )
        self.assertIsNone(handler._access_observation)
        observer_runtime.begin.assert_not_called()
        observer_runtime.record_boundary_failure.assert_called_once_with(
            "RuntimeError"
        )
        self.assertTrue(admission.allowed)

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
