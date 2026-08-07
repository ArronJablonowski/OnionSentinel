import sys
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_incident_read_model as model  # noqa: E402


class PortalIncidentReadModelTests(unittest.TestCase):
    def parse(self, query=None):
        return model.parse_incident_list_request(
            query or {}, max_per_page=500
        )

    def callbacks(self, asset_calls=None):
        calls = asset_calls if asset_calls is not None else []

        def resolve_asset(ip, observed_at, inventory):
            calls.append((ip, observed_at, inventory))
            return {"status": "resolved", "ip": ip, "observed_at": observed_at}

        return model.IncidentRowCallbacks(
            epoch=lambda value: float(value or 0),
            embedded_reviewer=lambda response, analysis: {
                "status": "embedded",
                "reviewer_error": "embedded error",
                "automation_authorization": {"source": "embedded"},
            },
            final_review_status=lambda reviewer, material, adjudication: (
                "adjudicated" if adjudication else "disagreed" if material else "reviewed"
            ),
            outcome_label=lambda outcome: f"Outcome: {outcome}",
            agent_display_state=lambda status, analysis_id, review_status: (
                str(status or "unknown"),
                f"{analysis_id}:{review_status}",
            ),
            reviewer_authorization=lambda reviewer: {
                "allowed": reviewer.get("status") == "complete"
            },
            resolve_asset_ip=resolve_asset,
        )

    def test_default_request_is_bounded_priority_page(self) -> None:
        request = self.parse()
        self.assertEqual(request.page, 1)
        self.assertEqual(request.per_page, 25)
        self.assertEqual(request.status, "all")
        self.assertEqual(request.sort, "priority")
        self.assertEqual(request.direction, "desc")
        self.assertEqual(request.where_sql, "")
        self.assertEqual(request.where_arguments, [])

    def test_page_and_limit_match_legacy_clamping(self) -> None:
        request = self.parse({"page": ["99"], "per_page": ["9999"]})
        self.assertEqual(request.page, 99)
        self.assertEqual(request.per_page, 500)
        fallback = self.parse({"page": ["bad"], "per_page": ["bad"]})
        self.assertEqual(fallback.page, 1)
        self.assertEqual(fallback.per_page, 25)

    def test_status_filter_uses_parameterized_where_clause(self) -> None:
        request = self.parse({"status": [" OPEN "]})
        self.assertEqual(request.status, "open")
        self.assertEqual(request.where_sql, "WHERE c.status = ?")
        self.assertEqual(request.where_arguments, ["open"])

    def test_invalid_policy_values_have_stable_errors(self) -> None:
        cases = (
            ({"status": ["deleted"]}, "Invalid incident status filter"),
            ({"sort": ["updated; DROP TABLE alerts"]}, "Invalid incident sort field"),
            ({"direction": ["sideways"]}, "Invalid incident sort direction"),
        )
        for query, message in cases:
            with self.subTest(query=query):
                with self.assertRaisesRegex(model.IncidentQueryError, message):
                    self.parse(query)

    def test_pagination_clamps_requested_page_to_available_data(self) -> None:
        request = self.parse({"page": ["10"], "per_page": ["25"]})
        self.assertEqual(request.pagination(51), (3, 3, 50))
        self.assertEqual(request.pagination(0), (1, 1, 0))

    def test_sort_sql_is_selected_only_from_allowlisted_expressions(self) -> None:
        source = self.parse({"sort": ["source"], "direction": ["asc"]})
        summary_sql = model.incident_order_sql(source, summary_ready=True)
        legacy_sql = model.incident_order_sql(source, summary_ready=False)
        self.assertIn("COALESCE(g.source_ip, a.source_ip, '')", summary_sql)
        self.assertIn(" ASC", summary_sql)
        self.assertTrue(legacy_sql.startswith("c.updated_at ASC"))
        self.assertEqual(
            model.incident_order_sql(self.parse(), summary_ready=False),
            model.PRIORITY_ORDER_SQL,
        )

    def test_optional_case_columns_keep_legacy_databases_readable(self) -> None:
        self.assertEqual(
            model.optional_case_selects(set()),
            (
                "NULL AS resolution_reason",
                "NULL AS resolved_at",
                "NULL AS resolved_by",
            ),
        )
        self.assertEqual(
            model.optional_case_selects(
                {"resolution_reason", "resolved_at", "resolved_by"}
            ),
            ("c.resolution_reason", "c.resolved_at", "c.resolved_by"),
        )

    def test_empty_schema_response_retains_requested_page_size(self) -> None:
        response = model.empty_incident_page(
            self.parse({"per_page": ["100"]})
        )
        self.assertFalse(response["schema_ready"])
        self.assertEqual(response["per_page"], 100)
        self.assertEqual(response["incidents"], [])

    def test_analysis_selection_requires_matching_group_and_role(self) -> None:
        item = {"latest_analysis_id": "analysis-1", "group_id": "group-1"}
        matching = {
            "analysis-1": {
                "analysis_id": "analysis-1",
                "group_id": "group-1",
                "agent_role": "incident-responder",
            }
        }
        self.assertEqual(
            model.select_incident_analysis(
                item, matching, {"group_id", "agent_role"}
            )["analysis_id"],
            "analysis-1",
        )
        for field, value in (("group_id", "group-2"), ("agent_role", "soc-analyst")):
            with self.subTest(field=field):
                analyses = {"analysis-1": {**matching["analysis-1"], field: value}}
                self.assertEqual(
                    model.select_incident_analysis(
                        item, analyses, {"group_id", "agent_role"}
                    ),
                    {},
                )

    def test_row_composition_preserves_evidence_review_and_asset_state(self) -> None:
        asset_calls = []
        item = {
            "case_id": "case-1",
            "group_id": "group-1",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "last_seen": "20",
            "raw_alert_count": 3,
            "total_seen_count": 7,
            "agent_status": "analyzing",
        }
        analysis = {
            "analysis_id": "analysis-1",
            "generated_at": "10",
            "model": "gpt-test",
            "detection_outcome": "suspicious",
            "confidence": "medium",
            "bluf": "Primary finding",
            "summary": "Evidence-backed summary",
            "evidence_hash": "sha256:test",
            "response_json": """{
                "event_status": "observed",
                "detection_validity": "valid",
                "activity_disposition": "suspicious",
                "handling": "investigate",
                "duplicate_of": "case-0",
                "incident_response_report": {"evidence_gaps": ["endpoint telemetry"]},
                "_incident_query_audit": {"partial": true}
            }""",
        }
        reviewer = {
            "status": "complete",
            "primary_outcome": "suspicious",
            "primary_confidence": "medium",
            "reviewer_outcome": "benign",
            "reviewer_confidence": "high",
            "agreement": "disagree",
            "material_disagreement": "true",
        }
        original_reviewer = dict(reviewer)
        adjudication = {"outcome_override": "malicious", "confidence": "high"}

        row = model.compose_incident_row(
            item,
            analysis,
            reviewer,
            adjudication,
            None,
            {"assets": "loaded"},
            None,
            self.callbacks(asset_calls),
        )

        self.assertEqual(reviewer, original_reviewer)
        self.assertEqual(row["seen_count"], 7)
        self.assertEqual(row["freshness_status"], "stale")
        self.assertEqual(row["coverage_status"], "gaps")
        self.assertEqual(row["evidence_gap_count"], 1)
        self.assertEqual(row["primary_event_status"], "observed")
        self.assertEqual(row["primary_duplicate_of"], "case-0")
        self.assertEqual(row["effective_outcome"], "malicious")
        self.assertEqual(row["effective_outcome_label"], "Outcome: malicious")
        self.assertEqual(row["final_review_status"], "adjudicated")
        self.assertTrue(row["material_disagreement"])
        self.assertEqual(row["automation_authorization"], {"allowed": True})
        self.assertEqual(row["agent_display_label"], "analysis-1:complete")
        self.assertEqual(len(asset_calls), 2)
        self.assertEqual(row["source_asset"]["ip"], "10.0.0.1")

    def test_fallback_review_is_the_effective_review_contract(self) -> None:
        fallback = {
            "primary_outcome": "benign",
            "primary_confidence": "low",
            "effective_outcome": "suspicious",
            "effective_confidence": "high",
            "reviewer_status": "fallback_complete",
            "reviewer_outcome": "suspicious",
            "reviewer_confidence": "high",
            "reviewer_agreement": "disagree",
            "material_disagreement": True,
            "final_review_status": "needs_adjudication",
            "automation_authorization": {"allowed": False},
            "adjudication": {"source": "fallback"},
        }
        row = model.compose_incident_row(
            {"agent_status": "analyzed"},
            {},
            {"status": "ignored"},
            {"source": "ignored"},
            fallback,
            {},
            None,
            self.callbacks(),
        )
        self.assertEqual(row["effective_outcome"], "suspicious")
        self.assertEqual(row["reviewer_status"], "fallback_complete")
        self.assertEqual(row["final_review_status"], "needs_adjudication")
        self.assertEqual(row["adjudication"], {"source": "fallback"})
        self.assertFalse(row["automation_authorization"]["allowed"])

    def test_inventory_failure_is_explicit_and_skips_resolution(self) -> None:
        asset_calls = []
        row = model.compose_incident_row(
            {
                "source_ip": "10.0.0.3",
                "destination_ip": "10.0.0.4",
                "updated_at": "30",
            },
            {},
            None,
            None,
            None,
            {},
            RuntimeError("inventory unavailable"),
            self.callbacks(asset_calls),
        )
        self.assertEqual(asset_calls, [])
        self.assertEqual(row["source_asset"]["status"], "inventory_unavailable")
        self.assertEqual(row["destination_asset"]["ip"], "10.0.0.4")
        self.assertEqual(row["freshness_status"], "not_analyzed")
        self.assertFalse(row["analysis_available"])


if __name__ == "__main__":
    unittest.main()
