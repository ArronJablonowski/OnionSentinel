from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "n8n" / "bin" / "run-local-ai-analysis.py"
ALERT_STORE = ROOT / "n8n" / "alert_store" / "alert_store.js"
WORKFLOW_CODE = ROOT / "n8n" / "workflows" / "code" / "investigation-enrichment.js"


def load_runner():
    sys.path.insert(0, str(RUNNER.parent))
    spec = importlib.util.spec_from_file_location("investigation_enrichment_runner", RUNNER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class InvestigationEnrichmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()

    def test_request_requires_evidence_bound_indicator(self) -> None:
        request = {
            "query_id": "enrich-ip",
            "backend": "enrichment",
            "purpose": "Determine whether the public destination has adverse reputation.",
            "parameters": {"indicator_type": "ip", "indicator": "198.51.100.9"},
        }
        context = {
            "permitted_observables": {
                "ips": ["198.51.100.9"], "domains": [], "hosts": [], "users": []
            }
        }
        normalized = self.runner.normalize_investigation_query_request(
            request,
            round_number=1,
            position=1,
            authorization_context=context,
        )
        self.assertEqual(normalized["parameters"]["indicator"], "198.51.100.9")
        request["parameters"]["indicator"] = "203.0.113.77"
        with self.assertRaisesRegex(
            self.runner.InvestigationQueryError,
            "not bound",
        ):
            self.runner.normalize_investigation_query_request(
                request,
                round_number=1,
                position=1,
                authorization_context=context,
            )

    def test_cache_hit_does_not_invoke_n8n(self) -> None:
        responses = [{
            "ok": True,
            "cache_complete": True,
            "records": [{
                "source": "otx",
                "indicator": "example.com",
                "indicator_type": "domain",
                "verdict": "unknown",
                "confidence": 0,
                "raw_response": {"pulse_info": {"count": 0}},
            }],
            "skipped": [],
        }]
        with mock.patch.object(
            self.runner,
            "_post_investigation_enrichment_json",
            side_effect=responses,
        ) as post:
            evidence = self.runner.collect_investigation_enrichment(
                {"parameters": {"indicator_type": "domain", "indicator": "example.com"}},
                {
                    "token": "x" * 64,
                    "alert_store_url": "http://127.0.0.1:8787",
                    "n8n_url": "http://127.0.0.1:5678/webhook/test",
                    "timeout": 10,
                },
            )
        self.assertEqual(post.call_count, 1)
        self.assertTrue(evidence["cache_checked_first"])
        self.assertFalse(evidence["n8n_invoked"])
        self.assertIn("provider_evidence", evidence["records"][0])

    def test_cache_miss_invokes_n8n_after_cache_check(self) -> None:
        responses = [
            {"ok": True, "cache_complete": False, "records": [], "misses": [{"source": "otx"}]},
            {
                "ok": True,
                "enrichment": {
                    "records": [{
                        "source": "otx",
                        "indicator": "example.com",
                        "indicator_type": "domain",
                        "verdict": "suspicious",
                        "confidence": 55,
                        "raw_response": {"pulse_info": {"count": 2}},
                    }],
                    "skipped": [],
                    "errors": [],
                },
            },
        ]
        with mock.patch.object(
            self.runner,
            "_post_investigation_enrichment_json",
            side_effect=responses,
        ) as post:
            evidence = self.runner.collect_investigation_enrichment(
                {"parameters": {"indicator_type": "domain", "indicator": "example.com"}},
                {
                    "token": "x" * 64,
                    "alert_store_url": "http://127.0.0.1:8787",
                    "n8n_url": "http://127.0.0.1:5678/webhook/test",
                    "timeout": 10,
                },
            )
        self.assertEqual(post.call_count, 2)
        self.assertIn("/investigations/enrichment/cache", post.call_args_list[0].args[0])
        self.assertIn("/webhook/test", post.call_args_list[1].args[0])
        self.assertTrue(evidence["n8n_invoked"])
        self.assertEqual(
            evidence["rate_limits_enforced_by"],
            "alert-store-persisted-provider-scheduler",
        )

    def test_runtime_has_double_cache_and_rate_limit_controls(self) -> None:
        alert_store = ALERT_STORE.read_text(encoding="utf-8")
        workflow = WORKFLOW_CODE.read_text(encoding="utf-8")
        self.assertIn("enrichmentCache.peek", alert_store)
        self.assertIn("cachedLookup(source, indicatorType, indicator", alert_store)
        self.assertIn("reserveProviderRateLimitSlot(source)", alert_store)
        self.assertIn("/investigations/enrichment/query", workflow)


if __name__ == "__main__":
    unittest.main()
