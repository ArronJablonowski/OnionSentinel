from __future__ import annotations

import sqlite3
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

from portal_incident_read_model import (  # noqa: E402
    IncidentListRequest,
    IncidentQueryError,
    IncidentRowCallbacks,
)
from portal_incident_read_service import (  # noqa: E402
    IncidentReadServiceSources,
    incident_detail_response,
    incident_list_response,
)
from portal_incident_repository import (  # noqa: E402
    IncidentCaseNotFound,
    IncidentDetailRecords,
    IncidentReviewRecords,
    IncidentSchemaUnavailable,
)


class IncidentReadServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.calls = []
        self.request = IncidentListRequest(1, 25, "all", "priority", "desc")
        self.list_records = SimpleNamespace(
            page=1,
            total=1,
            pages=1,
            status_counts={"open": 1},
            agent_status_counts={"analyzed": 1},
        )
        self.detail_records = IncidentDetailRecords(
            case={"case_id": "ir-unit"},
            analysis={"response_json": {"summary": "IR"}},
            prior_analysis={"response_json": {"summary": "SOC"}},
            review=IncidentReviewRecords("2026-08-08", {"status": "completed"}, None),
        )

        @contextmanager
        def connect():
            yield self.conn

        callbacks = IncidentRowCallbacks(
            epoch=lambda value: 0.0,
            embedded_reviewer=lambda *args: {},
            final_review_status=lambda *args: "completed",
            outcome_label=str,
            agent_display_state=lambda *args: ("analyzed", "analyzed"),
            reviewer_authorization=lambda value: {},
            resolve_asset_ip=lambda *args: {},
        )
        self.sources = IncidentReadServiceSources(
            connect=connect,
            api_error=lambda message, status=400: (
                status,
                {"ok": False, "error": message},
            ),
            parse_list_request=lambda query, **kwargs: self.request,
            schema_ready=lambda conn: True,
            empty_page=lambda request: {"ok": True, "schema_ready": False},
            load_list_records=lambda conn, request: self.list_records,
            load_inventory=lambda: ({"inventory_status": "fresh"}, None),
            compose_list_rows=lambda *args: [{"case_id": "ir-unit"}],
            load_detail_records=lambda conn, case_id: self.detail_records,
            parse_analysis_response=lambda analysis: dict(
                analysis.get("response_json") or {}
            ),
            compose_review_state=lambda *args: {"analysis_id": "analysis-unit"},
            review_defaults=lambda: {"reviewer_status": "not_requested"},
            row_callbacks=callbacks,
            render_incident_report=lambda *args: ("<article>IR</article>", 7),
            render_prior_analysis=lambda *args: "<article>SOC</article>",
            compose_detail_payload=lambda *args: {
                "ok": True,
                "case_id": args[0],
                "review": args[3],
                "incident_html": args[4],
                "prior_ai_html": args[5],
                "query_count": args[6],
            },
        )

    def tearDown(self) -> None:
        self.conn.close()

    def replace(self, **changes) -> IncidentReadServiceSources:
        values = dict(self.sources.__dict__)
        values.update(changes)
        return IncidentReadServiceSources(**values)

    def test_list_composes_bounded_public_page_and_inventory_status(self) -> None:
        status, response = incident_list_response(
            self.sources,
            {"page": ["1"]},
            max_per_page=100,
        )
        self.assertEqual(status, 200)
        self.assertEqual(response["incidents"], [{"case_id": "ir-unit"}])
        self.assertEqual(response["total"], 1)
        self.assertEqual(response["asset_inventory_status"], "fresh")
        self.assertTrue(response["schema_ready"])

    def test_list_preserves_successful_owner_order_and_payload_order(self) -> None:
        trace = []

        @contextmanager
        def connect():
            trace.append(("connect-enter",))
            yield self.conn
            trace.append(("connect-exit",))

        sources = self.replace(
            connect=connect,
            parse_list_request=lambda query, **kwargs: (
                trace.append(("parse", query, kwargs)) or self.request
            ),
            schema_ready=lambda conn: trace.append(("schema", conn)) or True,
            load_list_records=lambda conn, request: (
                trace.append(("records", conn, request)) or self.list_records
            ),
            load_inventory=lambda: (
                trace.append(("inventory",)) or ({"inventory_status": "fresh"}, None)
            ),
            review_defaults=lambda: (
                trace.append(("review-defaults",)) or {"reviewer_status": "none"}
            ),
            compose_list_rows=lambda *args: (
                trace.append(("compose", args)) or [{"case_id": "ir-unit"}]
            ),
        )

        status, response = incident_list_response(
            sources, {"page": ["1"]}, max_per_page=100,
        )

        self.assertEqual(status, 200)
        self.assertEqual(
            tuple(response),
            (
                "ok", "incidents", "page", "per_page", "total", "pages",
                "status_counts", "agent_status_counts", "schema_ready", "sort",
                "direction", "asset_inventory_status",
            ),
        )
        self.assertEqual(
            [event[0] for event in trace],
            [
                "parse", "connect-enter", "schema", "records", "inventory",
                "review-defaults", "compose", "connect-exit",
            ],
        )
        compose_args = trace[-2][1]
        self.assertIs(compose_args[0], self.conn)
        self.assertIs(compose_args[1], self.list_records)
        self.assertEqual(compose_args[2:5], (
            {"inventory_status": "fresh"}, None, {"reviewer_status": "none"},
        ))
        self.assertIs(compose_args[5], self.sources.row_callbacks)

    def test_list_inventory_status_precedence_is_exact(self) -> None:
        for inventory, error, expected in (
            ({"inventory_status": "fresh"}, "failed", "invalid"),
            ({"inventory_status": ""}, None, "loaded"),
            ({}, 0, "loaded"),
            ({"inventory_status": 7}, None, "7"),
        ):
            with self.subTest(inventory=inventory, error=error):
                sources = self.replace(
                    load_inventory=lambda: (inventory, error),
                )

                status, response = incident_list_response(
                    sources, {}, max_per_page=100,
                )

                self.assertEqual(status, 200)
                self.assertEqual(response["asset_inventory_status"], expected)

    def test_list_returns_empty_page_before_inventory_access_when_schema_absent(self) -> None:
        sources = self.replace(
            schema_ready=lambda conn: False,
            load_inventory=lambda: self.fail("inventory should not be loaded"),
        )
        status, response = incident_list_response(
            sources,
            {},
            max_per_page=100,
        )
        self.assertEqual(status, 200)
        self.assertFalse(response["schema_ready"])

    def test_list_preserves_query_validation_and_database_failure_statuses(self) -> None:
        def invalid(*args, **kwargs):
            raise IncidentQueryError("Invalid incident sort field")

        status, response = incident_list_response(
            self.replace(parse_list_request=invalid),
            {},
            max_per_page=100,
        )
        self.assertEqual(status, 400)
        self.assertIn("sort field", response["error"])

        def unavailable(*args, **kwargs):
            raise sqlite3.OperationalError("database unavailable")

        status, response = incident_list_response(
            self.replace(load_list_records=unavailable),
            {},
            max_per_page=100,
        )
        self.assertEqual(status, 503)
        self.assertIn("data unavailable", response["error"])

    def test_detail_normalizes_case_id_and_composes_rendered_payload(self) -> None:
        seen = []
        sources = self.replace(
            load_detail_records=lambda conn, case_id: (
                seen.append(case_id) or self.detail_records
            )
        )
        status, response = incident_detail_response(sources, " IR-Unit ")
        self.assertEqual(status, 200)
        self.assertEqual(seen, ["ir-unit"])
        self.assertEqual(response["case_id"], "ir-unit")
        self.assertEqual(response["query_count"], 7)
        self.assertEqual(response["review"]["analysis_id"], "analysis-unit")

    def test_detail_preserves_connection_and_composition_owner_order(self) -> None:
        trace = []

        @contextmanager
        def connect():
            trace.append(("connect-enter",))
            yield self.conn
            trace.append(("connect-exit",))

        def parse(analysis):
            owner = "primary" if analysis is self.detail_records.analysis else "prior"
            trace.append(("parse", owner, analysis))
            return {"owner": owner}

        sources = self.replace(
            connect=connect,
            load_detail_records=lambda conn, case_id: (
                trace.append(("load", conn, case_id)) or self.detail_records
            ),
            parse_analysis_response=parse,
            review_defaults=lambda: trace.append(("defaults",)) or {"default": True},
            compose_review_state=lambda *args: (
                trace.append(("review", args)) or {"review": True}
            ),
            render_incident_report=lambda *args: (
                trace.append(("incident-render", args)) or ("incident-html", 9)
            ),
            render_prior_analysis=lambda *args: (
                trace.append(("prior-render", args)) or "prior-html"
            ),
            compose_detail_payload=lambda *args: (
                trace.append(("payload", args)) or {"payload": list(args)}
            ),
        )

        status, response = incident_detail_response(sources, " IR-Unit ")

        self.assertEqual(status, 200)
        self.assertEqual(
            [event[0] for event in trace],
            [
                "connect-enter", "load", "connect-exit", "parse", "parse",
                "defaults", "review", "incident-render", "prior-render", "payload",
            ],
        )
        self.assertEqual(trace[1][2], "ir-unit")
        self.assertEqual(trace[3][1], "primary")
        self.assertEqual(trace[4][1], "prior")
        review_args = trace[6][1]
        self.assertIs(review_args[0], self.detail_records.case)
        self.assertIs(review_args[1], self.detail_records.analysis)
        self.assertEqual(review_args[2], {"owner": "primary"})
        self.assertEqual(review_args[6], {"default": True})
        self.assertIs(review_args[7], self.sources.row_callbacks)
        self.assertEqual(
            response["payload"],
            [
                "ir-unit", self.detail_records.case, {"owner": "primary"},
                {"review": True}, "incident-html", "prior-html", 9,
            ],
        )

    def test_detail_downstream_errors_remain_outside_database_error_mapping(self) -> None:
        trace = []

        @contextmanager
        def connect():
            trace.append("enter")
            yield self.conn
            trace.append("exit")

        def fail_after_load(analysis):
            raise sqlite3.OperationalError("parse failed")

        sources = self.replace(
            connect=connect,
            parse_analysis_response=fail_after_load,
        )

        with self.assertRaisesRegex(sqlite3.OperationalError, "parse failed"):
            incident_detail_response(sources, "ir-unit")
        self.assertEqual(trace, ["enter", "exit"])

    def test_detail_rejects_invalid_identity_before_database_access(self) -> None:
        sources = self.replace(
            connect=lambda: self.fail("database should not be opened")
        )
        status, response = incident_detail_response(sources, "../incident")
        self.assertEqual(status, 400)
        self.assertIn("Invalid incident case id", response["error"])

    def test_detail_maps_schema_missing_case_and_database_failures(self) -> None:
        for failure, expected, message in (
            (IncidentSchemaUnavailable("ir-unit"), 503, "schema"),
            (IncidentCaseNotFound("ir-unit"), 404, "not found"),
            (sqlite3.OperationalError("offline"), 503, "detail unavailable"),
            (FileNotFoundError("missing"), 503, "detail unavailable"),
        ):
            with self.subTest(expected=expected):
                def fail(*args, failure=failure, **kwargs):
                    raise failure

                status, response = incident_detail_response(
                    self.replace(load_detail_records=fail),
                    "ir-unit",
                )
                self.assertEqual(status, expected)
                self.assertIn(message, response["error"])


if __name__ == "__main__":
    unittest.main()
