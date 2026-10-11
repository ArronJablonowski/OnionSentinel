from __future__ import annotations

from live_osquery_contract_fixtures import (
    BIN,
    BoundedProcessError,
    LiveOsqueryClientError,
    LiveOsqueryContractError,
    Path,
    RELAY_AUTHORIZED_KEY,
    RELAY_BROKER,
    RELAY_INSTALLER,
    RELAY_LAUNCHER,
    RELAY_SUDOERS,
    ROOT,
    SO_AUTHORIZED_KEY,
    SO_CONFIG_EXAMPLE,
    SO_INSTALLER,
    SO_LAUNCHER,
    SO_WRAPPER,
    SimpleNamespace,
    ThreadPoolExecutor,
    _persist_live_osquery_artifact,
    capability_descriptor,
    collect_live_osquery,
    dt,
    harness_operator_approved,
    importlib,
    io,
    json,
    load_live_osquery_config,
    load_relay_broker,
    load_security_onion_wrapper,
    mock,
    normalize_query,
    normalize_requests,
    os,
    scheduled_inventory_approved,
    stat,
    subprocess,
    sys,
    tempfile,
    time,
    unittest,
    urllib,
    validate_result_artifact,
)

class SecurityOnionLiveOsqueryResponseTestsAllowsOnlyExplicitLoopbackHttpOrVerifiedHttpsCases:
    def test_allows_only_explicit_loopback_http_or_verified_https(self):
        base = {
            "enabled": True,
            "authorization_profile": self.wrapper.AUTHORIZATION_PROFILE,
            "kibana_url": "http://127.0.0.1:5601",
            "allow_loopback_http": True,
            "verify_tls": False,
            "target_aliases": {"endpoint-a": "agent-id"},
        }
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "config.json"
            path.write_text(json.dumps(base), encoding="utf-8")
            with mock.patch.object(
                self.wrapper,
                "_require_secure_regular_file",
            ):
                loaded = self.wrapper._load_config(path)
                self.assertEqual(loaded["kibana_url"], "http://127.0.0.1:5601")

                external = dict(base, kibana_url="http://192.168.1.7:5601")
                path.write_text(json.dumps(external), encoding="utf-8")
                with self.assertRaisesRegex(
                    self.wrapper.LiveQueryError,
                    "loopback-only",
                ):
                    self.wrapper._load_config(path)

                missing_profile = dict(base)
                missing_profile.pop("authorization_profile")
                path.write_text(json.dumps(missing_profile), encoding="utf-8")
                with self.assertRaisesRegex(
                    self.wrapper.LiveQueryError,
                    "authorization profile",
                ):
                    self.wrapper._load_config(path)

                unverified = dict(
                    base,
                    kibana_url="https://127.0.0.1:5601",
                    verify_tls=False,
                )
                path.write_text(json.dumps(unverified), encoding="utf-8")
                with self.assertRaisesRegex(
                    self.wrapper.LiveQueryError,
                    "TLS verification",
                ):
                    self.wrapper._load_config(path)


    def test_authorization_requires_the_dedicated_api_key_scheme(self):
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "authorization"
            with mock.patch.object(
                self.wrapper,
                "_require_secure_regular_file",
            ):
                path.write_text("ApiKey opaque-value\n", encoding="utf-8")
                self.assertEqual(
                    self.wrapper._load_authorization(path),
                    "ApiKey opaque-value",
                )
                path.write_text("Bearer opaque-value\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    self.wrapper.LiveQueryError,
                    "dedicated ApiKey",
                ):
                    self.wrapper._load_authorization(path)


    def test_expired_global_deadline_never_dispatches_http(self):
        with mock.patch.object(
            self.wrapper,
            "_http_json",
            side_effect=AssertionError("HTTP should not run after deadline"),
        ):
            result = self.wrapper._run_query(
                target_alias="endpoint-a",
                agent_id="agent-id",
                query="SELECT hostname FROM system_info LIMIT 1;",
                purpose="deadline test",
                config={
                    "kibana_url": "http://127.0.0.1:5601",
                    "query_timeout_seconds": 60,
                    "poll_seconds": 0.5,
                },
                authorization="ApiKey redacted",
                context=None,
                deadline=0.0,
            )
        self.assertEqual(result["status"], "timeout")
        self.assertIn("global batch deadline", result["error"])


    def test_http_transport_disables_proxies_and_redirects(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b'{"data":{}}'

        opener = mock.Mock()
        opener.open.return_value = FakeResponse()
        with mock.patch.object(
            self.wrapper.urllib.request,
            "build_opener",
            return_value=opener,
        ) as build_opener:
            self.assertEqual(
                self.wrapper._http_json(
                    method="GET",
                    url="http://127.0.0.1:5601/api/osquery/live_queries/id",
                    authorization="ApiKey redacted",
                    context=None,
                    timeout_seconds=5,
                ),
                {"data": {}},
            )
        handlers = build_opener.call_args.args
        proxy_handlers = [
            handler
            for handler in handlers
            if isinstance(handler, urllib.request.ProxyHandler)
        ]
        self.assertEqual(len(proxy_handlers), 1)
        self.assertEqual(proxy_handlers[0].proxies, {})
        self.assertTrue(
            any(isinstance(handler, self.wrapper._RejectRedirects) for handler in handlers)
        )

        redirect = urllib.error.HTTPError(
            "http://127.0.0.1:5601/api",
            302,
            "Found",
            {},
            io.BytesIO(),
        )
        opener.open.side_effect = redirect
        with (
            mock.patch.object(
                self.wrapper.urllib.request,
                "build_opener",
                return_value=opener,
            ),
            self.assertRaisesRegex(
                self.wrapper.LiveQueryError,
                "redirects are forbidden",
            ),
        ):
            self.wrapper._http_json(
                method="GET",
                url="http://127.0.0.1:5601/api",
                authorization="ApiKey redacted",
                context=None,
                timeout_seconds=5,
            )
        redirect.close()


    def test_eight_query_batch_shares_one_capped_deadline(self):
        requests = [
            {
                "target_alias": "endpoint-a",
                "query": f"SELECT hostname FROM system_info LIMIT {index + 1};",
                "purpose": f"deadline test {index}",
            }
            for index in range(8)
        ]
        deadlines: list[float] = []

        def fake_run_query(**kwargs):
            deadlines.append(kwargs["deadline"])
            return {
                "target_alias": kwargs["target_alias"],
                "query": kwargs["query"],
                "purpose": kwargs["purpose"],
                "status": "timeout",
                "rows": [],
                "total_rows": 0,
                "truncated": False,
                "duration_ms": 0,
                "error": "test",
            }

        with (
            mock.patch.object(self.wrapper.time, "monotonic", return_value=1000.0),
            mock.patch.object(self.wrapper, "_run_query", side_effect=fake_run_query),
        ):
            results = self.wrapper._run_batch(
                requests=requests,
                alias_map={"endpoint-a": "agent-id"},
                config={
                    "batch_timeout_seconds": 999,
                    "max_concurrent_queries": 4,
                },
                authorization="ApiKey redacted",
                context=None,
            )
        self.assertEqual(len(results), 8)
        self.assertEqual(set(deadlines), {1130.0})


