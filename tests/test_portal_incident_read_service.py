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
