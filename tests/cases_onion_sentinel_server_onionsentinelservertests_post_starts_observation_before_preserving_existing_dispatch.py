from __future__ import annotations

from onion_sentinel_server_fixtures import (
    DASHBOARD_DIR,
    Message,
    Path,
    ROOT,
    SimpleNamespace,
    hashlib,
    identity_module,
    importlib,
    json,
    mock,
    observer_runtime_module,
    os,
    principal_module,
    server,
    subprocess,
    sys,
    tempfile,
    unittest,
)

class OnionSentinelServerTestsPostStartsObservationBeforePreservingExistingDispatchCases:
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


    def test_rbac_authentication_maps_named_identity_without_client_role_input(self):
        viewer_password = "viewer password!"
        salt = b"0123456789abcdef"
        identity_store = identity_module.HumanIdentityStore(
            7,
            {
                "viewer.one": identity_module.HumanIdentity(
                    "viewer.one",
                    "viewer-1",
                    "viewer",
                    {
                        "algorithm": "pbkdf2_sha256",
                        "iterations": 200_000,
                        "salt": salt.hex(),
                        "hash": hashlib.pbkdf2_hmac(
                            "sha256",
                            viewer_password.encode(),
                            salt,
                            200_000,
                        ).hex(),
                    },
                )
            },
        )
        access = server._access_adapter.DedicatedAccessRuntime(
            runtime=SimpleNamespace(verify_admin_password=mock.Mock()),
            observer=SimpleNamespace(),
            sessions=SimpleNamespace(mode="rbac-enforce", enforcing=True),
            password_record={},
            identity_store=identity_store,
        )
        principal = access.authenticate("viewer.one", viewer_password)
        self.assertEqual(
            (principal.principal_id, principal.role), ("viewer-1", "viewer")
        )
        self.assertIsNone(access.authenticate("viewer.one", "wrong"))
        self.assertIsNone(access.authenticate("unknown", viewer_password))
        access.runtime.verify_admin_password.assert_not_called()


    def test_delegated_session_id_never_creates_legacy_admin_state(self):
        runtime = SimpleNamespace(
            create_admin_session=mock.Mock(return_value="legacy-session"),
            secrets=SimpleNamespace(
                token_urlsafe=mock.Mock(return_value="delegated-session")
            ),
        )
        access = server._access_adapter.DedicatedAccessRuntime(
            runtime=runtime,
            observer=SimpleNamespace(),
            sessions=SimpleNamespace(),
        )
        handler = SimpleNamespace(client_address=("127.0.0.1", 41414))
        viewer = principal_module.HumanPrincipal(
            "human_session", "viewer-1", "viewer"
        )
        administrator = principal_module.HumanPrincipal(
            "human_session", "local-administrator", "administrator"
        )
        self.assertEqual(
            access.create_browser_session_id(handler, viewer),
            "delegated-session",
        )
        runtime.create_admin_session.assert_not_called()
        self.assertEqual(
            access.create_browser_session_id(handler, administrator),
            "legacy-session",
        )
        runtime.create_admin_session.assert_called_once_with("127.0.0.1")


    def test_rbac_identity_generation_is_bound_to_new_sessions_at_startup(self):
        observer = SimpleNamespace(mode="rbac-enforce", enforcing=True)
        identity_store = identity_module.HumanIdentityStore(7, {})
        sessions = SimpleNamespace(mode="rbac-enforce", enforcing=True)
        with (
            mock.patch.object(
                server._access_adapter,
                "build_access_observer",
                return_value=observer,
            ),
            mock.patch.object(
                server._access_adapter,
                "load_enforcement_admin_password_record",
                return_value={},
            ),
            mock.patch.object(
                server._access_adapter, "validate_admin_session_store"
            ),
            mock.patch.object(
                server._access_adapter,
                "load_enforcement_human_identity_store",
                return_value=identity_store,
            ) as load_identities,
            mock.patch.object(
                server._access_adapter,
                "build_human_session_runtime",
                return_value=sessions,
            ) as build_sessions,
        ):
            built = server._access_adapter.build_access_runtime(
                environ={},
                home=Path("/operator"),
                application_logger=object(),
                runtime=server.runtime,
            )
        load_identities.assert_called_once_with(
            Path("/operator/n8n-local/config/onion-sentinel-human-identities.json")
        )
        self.assertEqual(build_sessions.call_args.kwargs["policy_generation"], 10)
        self.assertIs(built._identity_store, identity_store)


    def test_enforcement_get_auth_never_trusts_only_the_legacy_cookie(self):
        handler = SimpleNamespace(
            headers=Message(),
            client_address=("127.0.0.1", 41414),
            _admin_authenticated=mock.Mock(return_value=True),
            _admin_session_id=lambda: "session-" + "s" * 36,
        )
        sessions = SimpleNamespace(
            enforcing=True,
            resolve_read_session=mock.Mock(return_value=SimpleNamespace(
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

        observation.principal = principal_module.HumanPrincipal(
            "service_identity", "service-1", "administrator"
        )
        self.assertFalse(access.read_authenticated(handler))

        sessions.mode = "admin-enforce"
        sessions.resolve_read_session.reset_mock()
        self.assertTrue(access.read_authenticated(handler))
        sessions.resolve_read_session.assert_not_called()


    def test_admin_logout_bootstrap_sends_the_session_csrf_header(self):
        rendered = server.render_admin_status().decode("utf-8")
        self.assertIn("onion_sentinel_csrf=", rendered)
        self.assertIn("X-Onion-Sentinel-CSRF", rendered)
        self.assertIn("credentials:'same-origin'", rendered)
        self.assertIn("event.preventDefault()", rendered)

        viewer = server.render_session_status("viewer").decode("utf-8")
        self.assertIn("Authenticated as <strong>Viewer</strong>", viewer)
        self.assertIn('action="/admin/logout"', viewer)
        self.assertIn("X-Onion-Sentinel-CSRF", viewer)
        self.assertNotIn("Administration access is enabled", viewer)


    def test_enforcement_modes_have_an_isolated_clean_startup_boundary(self):
        for mode in ("admin-enforce", "rbac-enforce"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                self._assert_isolated_enforcement_startup(Path(tmp), mode)


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
        self.assertIn('name="username"', rendered)
        self.assertNotIn('name="role"', rendered)


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


