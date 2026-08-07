"""Direct contracts for SOC and Incident Responder read dispatch."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_read_dispatch import (  # noqa: E402
    SOC_READ_OPERATIONS,
    SocReadCallbacks,
    dispatch_soc_read,
)


class SocReadDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.calls: list[tuple] = []

        def pair(name):
            def callback(*args, **kwargs):
                self.calls.append((name, args, kwargs))
                return 206, {"operation": name}
            return callback

        self.callbacks = SocReadCallbacks(
            llm_current=lambda: {"operation": "current"},
            llm_logs=lambda query: {"operation": "logs", "query": query},
            alert_status=lambda: {"operation": "status"},
            settings_prompt=lambda path: {"ok": path.endswith("prompt")},
            agent_memory=pair("memory"),
            ai_settings=lambda: {"ok": True, "operation": "settings"},
            ollama_models=lambda refresh: {"refresh": refresh},
            alerts=lambda query: (207, b'{"already":"encoded"}'),
            alert_metrics=pair("metrics"),
            alert_suppressions=pair("suppressions"),
            incidents=pair("incidents"),
            reanalysis_runs=pair("runs"),
            incident_case_group=lambda case_id: (200, "abcdef123456"),
            api_error=lambda message, status: (status, {"error": message}),
            adjudication_history=pair("history"),
            incident_detail=pair("incident-detail"),
            alert_detail_fragment=pair("fragment"),
            alert_detail=pair("alert-detail"),
        )

    def dispatch(self, operation, *, resource_id=None, query=None, path="/prompt"):
        return dispatch_soc_read(
            operation,
            path=path,
            resource_id=resource_id,
            query=query or {},
            callbacks=self.callbacks,
        )

    def test_every_declared_operation_dispatches(self) -> None:
        for operation in SOC_READ_OPERATIONS:
            with self.subTest(operation=operation):
                self.assertIsNotNone(self.dispatch(operation, resource_id="ir-case"))
        self.assertIsNone(self.dispatch("soc_alert_events"))
        self.assertIsNone(self.dispatch(None))

    def test_encoded_alert_page_and_refresh_flag_are_preserved(self) -> None:
        alerts = self.dispatch("soc_alerts", query={"limit": ["10"]})
        models = self.dispatch("soc_ollama_models", query={"refresh": ["YES"]})

        self.assertEqual(alerts.status, 207)
        self.assertTrue(alerts.encoded)
        self.assertIsInstance(alerts.payload, bytes)
        self.assertTrue(models.payload["refresh"])

    def test_dynamic_adjudication_routes_preserve_limits_and_case_binding(self) -> None:
        self.dispatch(
            "incident_adjudications",
            resource_id="ir-one",
            query={"limit": ["invalid"]},
        )
        self.dispatch(
            "alert_adjudications",
            resource_id="abcdef123456",
            query={"limit": ["7"]},
        )

        self.assertIn(
            ("history", ("abcdef123456",), {"case_id": "ir-one", "limit": 25}),
            self.calls,
        )
        self.assertIn(
            ("history", ("abcdef123456",), {"limit": 7}),
            self.calls,
        )

    def test_missing_incident_case_becomes_existing_public_error(self) -> None:
        callbacks = SocReadCallbacks(
            **{
                **self.callbacks.__dict__,
                "incident_case_group": lambda case_id: (404, ""),
            }
        )
        result = dispatch_soc_read(
            "incident_adjudications",
            path="/api/soc-incidents/missing/adjudications",
            resource_id="missing",
            query={},
            callbacks=callbacks,
        )

        self.assertEqual(result.status, 404)
        self.assertEqual(result.payload["error"], "Incident case not found")

    def test_settings_health_status_preserves_failure_contract(self) -> None:
        result = self.dispatch("soc_settings_prompt", path="/not-ready")
        self.assertEqual(result.status, 500)


if __name__ == "__main__":
    unittest.main()
