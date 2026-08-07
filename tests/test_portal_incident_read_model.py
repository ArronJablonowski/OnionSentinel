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


if __name__ == "__main__":
    unittest.main()
