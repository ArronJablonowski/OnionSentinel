from __future__ import annotations

import re
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_query_runtime import (  # noqa: E402
    soc_alert_detail_fragment_response,
)


class ConnectionContext:
    def __init__(self, trace, connection) -> None:
        self.trace = trace
        self.connection = connection

    def __enter__(self):
        self.trace.append(("db_enter",))
        return self.connection

    def __exit__(self, exc_type, exc, traceback):
        self.trace.append(("db_exit", exc_type, exc, traceback))
        return False


class PortalSocQueryRuntimeTests(unittest.TestCase):
    group_id = "abcdef012345"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.detail_dir = Path(self.temp.name)
        self.detail_path = self.detail_dir / f"{self.group_id}.html"
        self.detail_path.write_text("base-detail", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def runtime(self, *, connect=None, review_state=None, layout_issues=None):
        trace = []
        default_review = {"state": "default"}
        selected_review = {"state": "selected"}
        connection = object()

        def api_error(message, status=400):
            trace.append(("api_error", message, status))
            return status, {"ok": False, "error": message}

        def review_defaults():
            trace.append(("review_defaults",))
            return default_review

        def db_connect():
            trace.append(("db_connect",))
            if isinstance(connect, BaseException):
                raise connect
            return ConnectionContext(trace, connection)

        def review_for_group(conn, group_id):
            trace.append(("review_for_group", conn, group_id))
            if isinstance(review_state, BaseException):
                raise review_state
            return selected_review

        def append_pcap(group_id, detail_html):
            trace.append(("append_pcap", group_id, detail_html))
            return f"pcap:{detail_html}"

        def collapse(detail_html):
            trace.append(("collapse", detail_html))
            return f"collapsed:{detail_html}"

        def panel(review, *, group_id):
            trace.append(("panel", review, group_id))
            return "<panel>"

        def validate(detail_html):
            trace.append(("validate", detail_html))
            return ["layout issue"] if layout_issues is None else layout_issues

        def layout_error(issues):
            trace.append(("layout_error", issues))
            return "<layout-error>"

        runtime = SimpleNamespace(
            re=re,
            sqlite3=sqlite3,
            SOC_ALERT_DETAIL_DIR=self.detail_dir,
            SOC_ALERT_DETAIL_FRAGMENT_MAX_BYTES=1024,
            SOC_ALERT_DETAIL_LAYOUT_VERSION="layout-v1",
            soc_alert_api_error=api_error,
            _soc_review_defaults=review_defaults,
            soc_alert_db_connect=db_connect,
            soc_alert_review_state_for_group=review_for_group,
            soc_alert_append_live_pcap_detail=append_pcap,
            soc_alert_collapse_detail_sections=collapse,
            render_analyst_review_panel=panel,
            soc_alert_validate_detail_layout_html=validate,
            soc_alert_layout_error_html=layout_error,
        )
        return runtime, trace, default_review, selected_review, connection

    def test_detail_fragment_preserves_review_render_layout_order_and_payload(self) -> None:
        runtime, trace, _, selected_review, connection = self.runtime()

        status, payload = soc_alert_detail_fragment_response(
            runtime,
            "  ABCDEF012345  ",
        )

        self.assertEqual(status, 200)
        self.assertEqual(list(payload), [
            "ok", "source", "group_id", "layout_version", "layout_valid",
            "layout_issues", "review", "detail_html",
        ])
        self.assertEqual(payload["group_id"], self.group_id)
        self.assertFalse(payload["layout_valid"])
        self.assertEqual(payload["layout_issues"], ["layout issue"])
        self.assertIs(payload["review"], selected_review)
        self.assertEqual(
            payload["detail_html"],
            "<layout-error><panel>collapsed:pcap:base-detail",
        )
        self.assertEqual(trace, [
            ("review_defaults",),
            ("db_connect",),
            ("db_enter",),
            ("review_for_group", connection, self.group_id),
            ("db_exit", None, None, None),
            ("append_pcap", self.group_id, "base-detail"),
            ("collapse", "pcap:base-detail"),
            ("panel", selected_review, self.group_id),
            ("validate", "<panel>collapsed:pcap:base-detail"),
            ("layout_error", ["layout issue"]),
        ])

    def test_detail_fragment_retains_default_review_for_only_suppressed_db_errors(self) -> None:
        for error in (FileNotFoundError("missing"), sqlite3.Error("database")):
            with self.subTest(error=type(error).__name__):
                runtime, trace, default_review, _, _ = self.runtime(connect=error)

                status, payload = soc_alert_detail_fragment_response(
                    runtime,
                    self.group_id,
                )

                self.assertEqual(status, 200)
                self.assertIs(payload["review"], default_review)
                self.assertEqual(trace[:2], [
                    ("review_defaults",),
                    ("db_connect",),
                ])
                self.assertEqual(trace[2][0], "append_pcap")

    def test_detail_fragment_propagates_non_database_review_failure(self) -> None:
        runtime, _, _, _, _ = self.runtime(
            review_state=RuntimeError("review owner failed")
        )

        with self.assertRaisesRegex(RuntimeError, "review owner failed"):
            soc_alert_detail_fragment_response(runtime, self.group_id)

    def test_detail_fragment_does_not_duplicate_existing_layout_error(self) -> None:
        self.detail_path.write_text("detail-layout-error", encoding="utf-8")
        runtime, trace, _, _, _ = self.runtime()

        status, payload = soc_alert_detail_fragment_response(runtime, self.group_id)

        self.assertEqual(status, 200)
        self.assertTrue(payload["layout_issues"])
        self.assertNotIn("layout_error", [event[0] for event in trace])

    def test_detail_fragment_rejects_invalid_id_before_runtime_path_access(self) -> None:
        runtime = SimpleNamespace(
            re=re,
            soc_alert_api_error=lambda message, status=400: (
                status,
                {"error": message},
            ),
        )

        self.assertEqual(
            soc_alert_detail_fragment_response(runtime, "not-an-id"),
            (400, {"error": "Invalid SOC alert group id"}),
        )


if __name__ == "__main__":
    unittest.main()
