from __future__ import annotations

from controlled_evaluation_runtime_fixtures import (
    ALERT_STORE,
    ALERT_STORE_DIR,
    BIN_DIR,
    BaseHTTPRequestHandler,
    CONTROLLED_CREDENTIAL_KEYS,
    CONTROLLED_ROUTE_FIELDS,
    DASHBOARD_SERVER,
    EVALUATION_TOKEN,
    INSTALLER_PATH,
    PIPELINE_ADAPTER_PATH,
    PRIMARY_ROUTE,
    Path,
    RELEASE_ID,
    REPLACEMENT_RELEASE_ID,
    REVIEWER_ROUTE,
    ROOT,
    RUNNER_PATH,
    SCHEDULER_PATH,
    SCORING_RULES,
    SimpleNamespace,
    ThreadingHTTPServer,
    available_port,
    closing,
    dt,
    hashlib,
    importlib,
    io,
    json,
    load_python_module,
    mock,
    os,
    process_output,
    raw_request_status,
    request_json,
    request_json_bytes,
    request_status,
    sanitized_environment,
    shutil,
    socket,
    sqlite3,
    startup_failure_diagnostic,
    stop_process,
    subprocess,
    sys,
    tempfile,
    threading,
    time,
    unittest,
    urllib,
    write_controlled_route_fixture,
)

class ControlledDashboardTestsHealthIdentifiesExactRuntimeAndAllOtherReadsAreBlockedCases:
    def test_health_identifies_exact_runtime_and_all_other_reads_are_blocked(
        self,
    ) -> None:
        status, health = request_json(f"{self.base_url}/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(health["service"], "onion-sentinel")
        self.assertTrue(health["controlled_evaluation"])
        self.assertEqual(health["release_id"], RELEASE_ID)
        self.assertEqual(health["listen_host"], "127.0.0.1")
        self.assertEqual(health["listen_port"], self.port)
        self.assertEqual(
            health["alert_store_origin"],
            f"http://127.0.0.1:{self.alert_store_port}",
        )
        self.assertEqual(
            health["dispatch_route_patterns"],
            [
                "POST /api/soc-alerts/{12hex}/analyze",
                "POST /api/soc-incidents/{case_id}/reanalyze",
            ],
        )
        self.assertTrue(health["dashboard_ready"])
        self.assertTrue(health["alert_store_ready"])
        self.assertEqual(
            health["alert_store_health"],
            {
                "status": "ready",
                "service": "onion-sentinel-alert-store",
                "controlled_evaluation": True,
                "runtime_mode": "controlled-evaluation",
                "release_id": RELEASE_ID,
                "listen_host": "127.0.0.1",
                "listen_port": self.alert_store_port,
                "accepting_requests": True,
            },
        )
        self.assertEqual(
            request_json(
                f"{self.base_url}/healthz?unexpected=1"
            )[0],
            403,
        )
        self.assertEqual(
            request_status(
                f"{self.base_url}/healthz?unexpected=1",
                "HEAD",
            ),
            403,
        )
        for target in (
            "/healthz?",
            "/healthz;",
            "/healthz#fragment",
            "//healthz",
        ):
            with self.subTest(raw_target=target):
                self.assertEqual(
                    raw_request_status(
                        "127.0.0.1",
                        self.port,
                        target,
                    ),
                    403,
                )
                self.assertEqual(
                    raw_request_status(
                        "127.0.0.1",
                        self.port,
                        target,
                        "HEAD",
                    ),
                    403,
                )

        for route in (
            "/",
            "/index.html",
            "/api/soc-alerts",
            "/api/llm-analysis/current",
            "/admin",
        ):
            with self.subTest(route=route):
                self.assertEqual(
                    request_json(f"{self.base_url}{route}")[0],
                    403,
                )
                self.assertEqual(
                    request_status(
                        f"{self.base_url}{route}",
                        "HEAD",
                    ),
                    403,
                )


    def test_health_fails_closed_for_downstream_identity_and_availability(
        self,
    ) -> None:
        original_release = self.alert_store_health["release_id"]
        try:
            self.alert_store_health["release_id"] = "d" * 40
            status, health = request_json(f"{self.base_url}/healthz")
            self.assertEqual(status, 503, health)
            self.assertFalse(health["ok"])
            self.assertFalse(health["alert_store_ready"])
            self.assertEqual(
                health["alert_store_health"]["status"],
                "identity_mismatch",
            )
            self.assertEqual(
                health["alert_store_health"]["release_id"],
                "d" * 40,
            )
        finally:
            self.alert_store_health["release_id"] = original_release

        try:
            self.alert_store_health_available = False
            status, health = request_json(f"{self.base_url}/healthz")
            self.assertEqual(status, 503, health)
            self.assertFalse(health["ok"])
            self.assertFalse(health["alert_store_ready"])
            self.assertEqual(
                health["alert_store_health"],
                {"status": "unavailable"},
            )
        finally:
            self.alert_store_health_available = True

        status, health = request_json(f"{self.base_url}/healthz")
        self.assertEqual(status, 200, health)
        self.assertTrue(health["alert_store_ready"])


    def test_controlled_dispatch_requires_ephemeral_token_before_downstream(
        self,
    ) -> None:
        route = "/api/soc-alerts/0123456789ab/analyze"
        before = self.alert_store_post_count
        for label, token in (
            ("missing", ""),
            ("wrong", "8" * 64),
        ):
            with self.subTest(label=label):
                status, response = request_json(
                    f"{self.base_url}{route}",
                    "POST",
                    {},
                    evaluation_token=token,
                )
                self.assertEqual(status, 403, response)
                self.assertEqual(
                    response["error"],
                    "controlled evaluation authorization failed",
                )
                self.assertEqual(self.alert_store_post_count, before)


    def test_only_exact_dispatch_post_shapes_pass_the_route_guard(self) -> None:
        blocked = (
            "/api/soc-settings/ai-model",
            "/api/soc-alerts/0123456789ab/ack",
            "/api/soc-alerts/0123456789ab/escalate",
            "/api/soc-alerts/not-12hex/analyze",
            "/api/soc-incidents/reanalyze-all",
            "/api/soc-incidents/not-a-case/reanalyze",
            "/api/soc-alerts/0123456789ab/analyze?unexpected=1",
            "/api/soc-incidents/ir-synthetic/reanalyze?unexpected=1",
        )
        for route in blocked:
            with self.subTest(route=route):
                status, response = request_json(
                    f"{self.base_url}{route}",
                    "POST",
                    {},
                    request_headers={
                        "X-Onion-Sentinel-Request": "dashboard",
                        "Sec-Fetch-Site": "same-origin",
                        "Origin": self.base_url,
                    },
                )
                self.assertEqual(status, 403, response)

        for target in (
            "/api/soc-alerts/0123456789ab/analyze?",
            "/api/soc-alerts/0123456789ab/analyze;",
            "/api/soc-incidents/ir-synthetic/reanalyze?",
            "/api/soc-incidents/ir-synthetic/reanalyze;",
            "//api/soc-alerts/0123456789ab/analyze",
            "//api/soc-incidents/ir-synthetic/reanalyze",
        ):
            with self.subTest(raw_target=target):
                self.assertEqual(
                    raw_request_status(
                        "127.0.0.1",
                        self.port,
                        target,
                        "POST",
                    ),
                    403,
                )

        # The fake downstream returns 503 for every mutation. Exact dispatch
        # shapes therefore prove they crossed the evaluation route guard.
        allowed = (
            "/api/soc-alerts/0123456789ab/analyze",
            "/api/soc-incidents/ir-synthetic/reanalyze",
        )
        for route in allowed:
            with self.subTest(allowed_route=route):
                before = self.alert_store_post_count
                status, response = request_json(
                    f"{self.base_url}{route}",
                    "POST",
                    {},
                    request_headers={
                        "X-Onion-Sentinel-Request": "dashboard",
                        "Sec-Fetch-Site": "same-origin",
                        "Origin": self.base_url,
                    },
                )
                self.assertNotEqual(status, 403, response)
                if route.startswith("/api/soc-alerts/"):
                    self.assertEqual(
                        self.alert_store_post_count,
                        before + 1,
                    )
                else:
                    # The synthetic dashboard database contains no incident
                    # case, so this exact route is accepted and terminates
                    # locally before a downstream request is needed.
                    self.assertEqual(self.alert_store_post_count, before)
