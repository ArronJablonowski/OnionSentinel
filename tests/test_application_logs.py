from __future__ import annotations

import importlib
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "onion-sentinel-dashboard"


def load_application_logs():
    spec = importlib.util.spec_from_file_location(
        "onion_sentinel_application_logs_test",
        DASHBOARD_DIR / "application_logs.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


application_logs = load_application_logs()


def _fifo_content_worker(home: str, output: multiprocessing.Queue) -> None:
    """Run a FIFO read out of process so a regression cannot hang pytest."""
    try:
        application_logs.content_response(
            "onion-sentinel-application",
            home=Path(home),
        )
    except application_logs.ApplicationLogError as exc:
        output.put(("error", exc.status))
    except BaseException as exc:  # pragma: no cover - diagnostic safety net
        output.put(("unexpected", type(exc).__name__))
    else:
        output.put(("ok", 200))


class ApplicationLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name)
        self.runtime_root = self.home / "n8n-local" / "logs"
        self.analysis_root = (
            self.home
            / "n8n-local"
            / "soc-alerts"
            / "llm-analysis-logs"
        )
        self.runtime_root.mkdir(parents=True, mode=0o700)
        self.analysis_root.mkdir(parents=True, mode=0o700)
        os.chmod(self.runtime_root, 0o700)
        os.chmod(self.analysis_root, 0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def catalog_item(self, log_id: str) -> dict:
        response = application_logs.catalog_response(home=self.home)
        return next(item for item in response["logs"] if item["id"] == log_id)

    def write_runtime(self, basename: str, content: str | bytes) -> Path:
        path = self.runtime_root / basename
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def test_catalog_is_fixed_unique_and_confined_to_runtime_roots(self) -> None:
        response = application_logs.catalog_response(home=self.home)

        self.assertTrue(response["ok"])
        self.assertRegex(response["generated_at"], r"^\d{4}-\d{2}-\d{2}T")
        logs = response["logs"]
        ids = [item["id"] for item in logs]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 40)
        self.assertIn("onion-sentinel-application", ids)
        self.assertIn("llm-analysis", ids)
        self.assertIn("ensure-stack-runs", ids)

        allowed_roots = (self.runtime_root, self.analysis_root)
        for item in logs:
            self.assertTrue(application_logs.is_application_log_id(item["id"]))
            path = Path(item["path"])
            self.assertTrue(
                any(path == root / path.name for root in allowed_roots),
                item,
            )
            self.assertIn("rotation", item)
            self.assertIn("retention", item)
            self.assertIsInstance(item["members"], list)

    def test_ids_and_content_lookup_reject_unknown_or_traversal_values(self) -> None:
        self.write_runtime("onion-sentinel-application.jsonl", "safe\n")
        for value in (
            "",
            "unknown-log",
            "../onion-sentinel-application",
            "onion-sentinel-application/1",
            r"onion-sentinel-application\1",
            "%2e%2e",
            ".",
        ):
            self.assertFalse(application_logs.is_application_log_id(value), value)
            with self.assertRaises(application_logs.ApplicationLogError) as raised:
                application_logs.content_response(value, home=self.home)
            self.assertEqual(raised.exception.status, 404)

        for member in (
            "../current",
            "onion-sentinel-application.jsonl",
            "/etc/passwd",
            r"..\current",
            "6",
        ):
            with self.assertRaises(application_logs.ApplicationLogError) as raised:
                application_logs.content_response(
                    "onion-sentinel-application",
                    member=member,
                    home=self.home,
                )
            self.assertEqual(raised.exception.status, 404)

    def test_tail_is_line_and_byte_bounded_and_returns_newest_content(self) -> None:
        lines = [f"line-{index:04d}-" + ("x" * 1100) for index in range(650)]
        self.write_runtime(
            "onion-sentinel-application.jsonl",
            "\n".join(lines) + "\n",
        )

        response = application_logs.content_response(
            "onion-sentinel-application",
            lines=100_000,
            home=self.home,
        )

        self.assertTrue(response["ok"])
        self.assertLessEqual(response["line_count"], application_logs.MAX_TAIL_LINES)
        self.assertLessEqual(response["returned_bytes"], application_logs.MAX_TAIL_BYTES)
        self.assertLessEqual(
            len(response["content"].encode("utf-8")),
            application_logs.MAX_TAIL_BYTES,
        )
        self.assertTrue(response["truncated"])
        self.assertIn("line-0649", response["content"])
        self.assertNotIn("line-0000", response["content"])

        newest_three = application_logs.content_response(
            "onion-sentinel-application",
            lines=3,
            home=self.home,
        )
        self.assertEqual(newest_three["line_count"], 3)
        self.assertIn("line-0647", newest_three["content"])
        self.assertIn("line-0649", newest_three["content"])
        self.assertNotIn("line-0646", newest_three["content"])

    def test_tail_handles_invalid_utf8_and_redacts_common_credentials(self) -> None:
        private_key = (
            b"-----BEGIN " + b"RSA PRIVATE KEY-----\n"
            b"private-key-material\n"
            b"-----END " + b"RSA PRIVATE KEY-----\n"
        )
        content = (
            b"ordinary line\n"
            b"Authorization: Bearer bearer-secret\n"
            b"Cookie: session=cookie-secret\n"
            b"password=assignment-secret failed\n"
            b'{"token":"json-secret","client_secret":"json-client-secret"}\n'
            + private_key
            + b"invalid-utf8=\xff\n"
        )
        self.write_runtime("onion-sentinel-application.jsonl", content)

        response = application_logs.content_response(
            "onion-sentinel-application",
            lines=100,
            home=self.home,
        )
        rendered = response["content"]

        self.assertTrue(response["redacted"])
        for secret in (
            "bearer-secret",
            "cookie-secret",
            "assignment-secret",
            "json-secret",
            "json-client-secret",
            "private-key-material",
        ):
            self.assertNotIn(secret, rendered)
        self.assertIn("[REDACTED", rendered)
        self.assertIn("\ufffd", rendered)

    def test_invalid_utf8_expansion_cannot_exceed_response_byte_cap(self) -> None:
        # Each invalid input byte becomes a three-byte UTF-8 replacement
        # character. The post-decode cap must account for a slice beginning in
        # the middle of one replacement sequence as well as that expansion.
        self.write_runtime(
            "onion-sentinel-application.jsonl",
            b"\xff" * (application_logs.MAX_TAIL_BYTES + 100),
        )

        response = application_logs.content_response(
            "onion-sentinel-application",
            lines=application_logs.MAX_TAIL_LINES,
            home=self.home,
        )

        actual = len(response["content"].encode("utf-8"))
        self.assertLessEqual(actual, application_logs.MAX_TAIL_BYTES)
        self.assertEqual(response["returned_bytes"], actual)
        self.assertTrue(response["truncated"])

    def test_numbered_rotation_members_are_fixed_and_readable(self) -> None:
        base = "onion-sentinel-application.jsonl"
        self.write_runtime(base, "current\n")
        self.write_runtime(f"{base}.1", "backup-one\n")
        self.write_runtime(f"{base}.5", "backup-five\n")
        self.write_runtime(f"{base}.6", "not-allowlisted\n")

        item = self.catalog_item("onion-sentinel-application")
        member_ids = [member["id"] for member in item["members"]]
        self.assertEqual(member_ids, ["current", "1", "5"])
        self.assertEqual(item["member_count"], 3)
        self.assertEqual(
            item["retained_size_bytes"],
            sum((self.runtime_root / name).stat().st_size for name in (base, f"{base}.1", f"{base}.5")),
        )

        response = application_logs.content_response(
            "onion-sentinel-application",
            member="1",
            home=self.home,
        )
        self.assertEqual(response["member"], "1")
        self.assertEqual(response["content"], "backup-one")

    def test_alert_store_rotation_reads_only_whitelisted_env_settings(self) -> None:
        env_path = self.home / "n8n-local" / ".env"
        env_path.write_text(
            # The host runner exports assignments in file order, so the last
            # duplicate is the effective process value and must be displayed.
            "ALERT_STORE_APPLICATION_LOG_MAX_BYTES=1048576\n"
            "ALERT_STORE_APPLICATION_LOG_BACKUPS=4\n"
            "TELEGRAM_BOT_TOKEN=must-never-be-returned\n"
            "ALERT_STORE_APPLICATION_LOG_MAX_BYTES=2097152\n"
            "ALERT_STORE_APPLICATION_LOG_BACKUPS=2\n",
            encoding="utf-8",
        )
        os.chmod(env_path, 0o600)
        base = "alert-store-application.jsonl"
        self.write_runtime(base, "current\n")
        self.write_runtime(f"{base}.2", "last configured backup\n")
        self.write_runtime(f"{base}.3", "outside configured policy\n")

        response = application_logs.catalog_response(home=self.home)
        serialized = json.dumps(response)
        item = next(entry for entry in response["logs"] if entry["id"] == "alert-store-application")
        self.assertIn("2,097,152 bytes", item["rotation"])
        self.assertEqual([member["id"] for member in item["members"]], ["current", "2"])
        self.assertNotIn("must-never-be-returned", serialized)

    def test_symlink_and_directory_members_are_not_cataloged_or_read(self) -> None:
        outside = self.home / "outside.log"
        outside.write_text("outside-secret\n", encoding="utf-8")
        link = self.runtime_root / "onion-sentinel-application.jsonl"
        link.symlink_to(outside)

        item = self.catalog_item("onion-sentinel-application")
        self.assertFalse(item["exists"])
        self.assertEqual(item["members"], [])
        with self.assertRaises(application_logs.ApplicationLogError) as raised:
            application_logs.content_response(
                "onion-sentinel-application",
                home=self.home,
            )
        self.assertEqual(raised.exception.status, 403)

        link.unlink()
        link.mkdir()
        item = self.catalog_item("onion-sentinel-application")
        self.assertFalse(item["exists"])
        with self.assertRaises(application_logs.ApplicationLogError) as raised:
            application_logs.content_response(
                "onion-sentinel-application",
                home=self.home,
            )
        self.assertEqual(raised.exception.status, 403)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO test requires os.mkfifo")
    def test_fifo_member_is_rejected_without_blocking(self) -> None:
        fifo = self.runtime_root / "onion-sentinel-application.jsonl"
        os.mkfifo(fifo, 0o600)
        output: multiprocessing.Queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=_fifo_content_worker,
            args=(str(self.home), output),
        )
        process.start()
        process.join(timeout=2.0)
        try:
            self.assertFalse(
                process.is_alive(),
                "reading a nonregular allowlisted member blocked on a FIFO",
            )
            self.assertEqual(output.get(timeout=1.0), ("error", 403))
        finally:
            if process.is_alive():
                process.terminate()
                process.join(timeout=1.0)
            output.close()

    def test_ensure_stack_family_is_pattern_limited_and_catalog_bounded(self) -> None:
        valid_names = []
        for index in range(application_logs.MAX_FAMILY_MEMBERS + 3):
            # Calendar validity is irrelevant to the fixed filename contract;
            # the digits simply provide deterministic newest-first names.
            name = f"ensure-n8n-stack-202607{index + 1:02d}-120000Z.log"
            valid_names.append(name)
            self.write_runtime(name, f"run-{index}\n")
        self.write_runtime("ensure-n8n-stack-latest.log", "invalid-name\n")
        self.write_runtime("ensure-n8n-stack-20260731-120000Z.log.bak", "invalid-suffix\n")
        outside = self.home / "outside-family.log"
        outside.write_text("outside\n", encoding="utf-8")
        (self.runtime_root / "ensure-n8n-stack-20990101-000000Z.log").symlink_to(outside)

        item = self.catalog_item("ensure-stack-runs")
        self.assertEqual(item["member_count"], len(valid_names))
        self.assertEqual(len(item["members"]), application_logs.MAX_FAMILY_MEMBERS)
        self.assertEqual(item["omitted_member_count"], 3)
        self.assertTrue(
            all(application_logs.ENSURE_STACK_RE.fullmatch(member["id"]) for member in item["members"])
        )
        self.assertFalse(any(member["path"].endswith(".bak") for member in item["members"]))

        selected = item["members"][0]
        response = application_logs.content_response(
            "ensure-stack-runs",
            member=selected["id"],
            lines=10,
            home=self.home,
        )
        self.assertEqual(response["member"], selected["id"])
        with self.assertRaises(application_logs.ApplicationLogError) as raised:
            application_logs.content_response(
                "ensure-stack-runs",
                member="ensure-n8n-stack-../../etc/passwd",
                home=self.home,
            )
        self.assertEqual(raised.exception.status, 404)

    def test_root_must_be_owner_controlled_directory(self) -> None:
        os.chmod(self.runtime_root, 0o777)
        with self.assertRaises(application_logs.ApplicationLogError) as raised:
            application_logs.catalog_response(home=self.home)
        self.assertEqual(raised.exception.status, 403)


class ApplicationLogServerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(DASHBOARD_DIR))
        cls.server = importlib.import_module("onion_sentinel_server")

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            sys.path.remove(str(DASHBOARD_DIR))
        except ValueError:
            pass

    def test_log_routes_are_exact_and_reject_encoded_nested_ids(self) -> None:
        server = self.server
        self.assertTrue(server.is_application_log_get_api("/api/application-logs"))
        self.assertTrue(
            server.is_application_log_get_api(
                "/api/application-logs/onion-sentinel-application"
            )
        )
        self.assertEqual(
            server.application_log_route_identifier(
                "/api/application-logs/onion-sentinel-application"
            ),
            "onion-sentinel-application",
        )
        for path in (
            "/api/application-logs/",
            "/api/application-logs/unknown-log",
            "/api/application-logs/onion-sentinel-application/1",
            "/api/application-logs/onion-sentinel-application%2F1",
            "/api/application-logs/onion-sentinel-application%5C1",
            "/api/application-logs/%2e%2e",
        ):
            self.assertFalse(server.is_application_log_get_api(path), path)
            self.assertIsNone(server.application_log_route_identifier(path), path)

    def handler_for(self, path: str, *, authenticated: bool):
        handler = object.__new__(self.server.OnionSentinelHandler)
        handler.path = path
        handler._admin_authenticated = lambda: authenticated
        responses = []

        def send(status, body, content_type="text/html; charset=utf-8", extra=None):
            responses.append((int(status), body, content_type, extra))
            return None

        handler._send = send
        return handler, responses

    def test_catalog_and_content_routes_are_admin_gated(self) -> None:
        for path in (
            "/api/application-logs",
            "/api/application-logs/onion-sentinel-application?member=current&lines=100",
        ):
            handler, responses = self.handler_for(path, authenticated=False)
            self.server.OnionSentinelHandler.do_GET(handler)
            self.assertEqual(responses[0][0], 403, path)
            payload = json.loads(responses[0][1])
            self.assertFalse(payload["ok"])
            self.assertTrue(payload["authentication_required"])

    def test_authenticated_handler_uses_catalog_and_bounded_content_helpers(self) -> None:
        handler, responses = self.handler_for(
            "/api/application-logs",
            authenticated=True,
        )
        with mock.patch.object(
            self.server.application_logs,
            "catalog_response",
            return_value={"ok": True, "logs": []},
        ) as catalog:
            self.server.OnionSentinelHandler.do_GET(handler)
        catalog.assert_called_once_with()
        self.assertEqual(responses[0][0], 200)

        handler, responses = self.handler_for(
            "/api/application-logs/onion-sentinel-application?member=1&lines=999999",
            authenticated=True,
        )
        with mock.patch.object(
            self.server.application_logs,
            "content_response",
            return_value={"ok": True, "content": "tail"},
        ) as content:
            self.server.OnionSentinelHandler.do_GET(handler)
        content.assert_called_once_with(
            "onion-sentinel-application",
            member="1",
            lines=self.server.application_logs.MAX_TAIL_LINES,
        )
        self.assertEqual(responses[0][0], 200)


class ApplicationLogPageContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = (
            DASHBOARD_DIR / "scripts" / "build_soc_alerts_dashboard.py"
        ).read_text(encoding="utf-8")
        cls.shell = (
            DASHBOARD_DIR / "scripts" / "dashboard_shell_components.py"
        ).read_text(encoding="utf-8")
        start = cls.builder.index("def logs_page_section()")
        end = cls.builder.index("\n\nALERTS_REACTIVE_FALLBACK", start)
        cls.section = cls.builder[start:end]

    def test_logs_page_is_in_navigation_and_uses_fixed_api(self) -> None:
        self.assertIn(
            "PageDefinition('logs', 'logs.html', 'Onion Sentinel Logs'",
            self.shell,
        )
        self.assertIn("elif page_key == 'logs':", self.builder)
        self.assertIn("replace_main_page_content(rendered, logs_page_section())", self.builder)
        self.assertIn("const CATALOG_ENDPOINT='/api/application-logs'", self.section)
        self.assertIn(
            "`${CATALOG_ENDPOINT}/${encodeURIComponent(String(view.item.id??''))}",
            self.section,
        )
        self.assertNotIn("/api/application-logs?path=", self.section)

    def test_log_content_is_lazy_admin_aware_and_rendered_as_text(self) -> None:
        self.assertIn("details.addEventListener('toggle'", self.section)
        self.assertIn("if(details.open&&!view.loaded)void loadLog(view)", self.section)
        self.assertIn("[100,200,500]", self.section)
        self.assertIn("response.status===403", self.section)
        self.assertIn("/admin/login?resume=logs", self.section)
        self.assertIn("element.textContent=String(text)", self.section)
        self.assertNotIn(".innerHTML", self.section)
        self.assertIn("cache:'no-store',credentials:'same-origin'", self.section)

    def test_deployment_copies_log_module_into_dedicated_dashboard_runtime(self) -> None:
        installer = (
            ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'cp "$REPO_DIR/onion-sentinel-dashboard/application_logs.py" '
            '"$DASHBOARD_RUNTIME_DIR/application_logs.py"',
            installer,
        )
        transitional = (DASHBOARD_DIR / "report_portal.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("/api/application-logs", transitional)


if __name__ == "__main__":
    unittest.main()
