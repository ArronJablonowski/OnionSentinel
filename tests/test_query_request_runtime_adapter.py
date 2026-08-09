#!/usr/bin/env python3
"""Characterization tests for query request compatibility binding."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
if str(N8N_ROOT) not in sys.path:
    sys.path.insert(0, str(N8N_ROOT))

from onion_sentinel.analysis.query import request_runtime_adapter


class QueryRequestRuntimeAdapterTests(unittest.TestCase):
    def test_legacy_fields_are_consumed_in_stable_order(self) -> None:
        response = {
            "investigation_query_requests": [{"query_id": "unified"}],
            "pcap_query_requests": [{"operation": "dns"}, "invalid-pcap"],
            "live_osquery_requests": [{
                "target_alias": "endpoint-a", "query": "SELECT 1",
                "purpose": "  Inspect endpoint  ",
            }],
            "analysis": "preserved",
        }
        result = request_runtime_adapter.pop_requests(
            {"_query_text": lambda value, limit: str(value).strip()[:limit]},
            response,
        )
        self.assertEqual([item.get("query_id") if isinstance(item, dict) else item for item in result], [
            "unified", "legacy-pcap-1", "invalid-pcap", "legacy-osquery-1",
        ])
        self.assertEqual(result[1]["backend"], "pcap_zeek")
        self.assertEqual(result[3]["parameters"], {
            "target_alias": "endpoint-a", "query": "SELECT 1",
        })
        self.assertEqual(result[3]["purpose"], "Inspect endpoint")
        self.assertEqual(response, {"analysis": "preserved"})

    def test_nonlist_unified_value_is_preserved_for_fail_closed_validation(self) -> None:
        response = {"investigation_query_requests": "malformed"}
        self.assertEqual(
            request_runtime_adapter.pop_requests(
                {"_query_text": lambda value, _limit: str(value)}, response),
            ["malformed"],
        )

    def test_backend_dispatch_preserves_authorization_context(self) -> None:
        security = mock.Mock(return_value=({"pack": "dns"}, {"bound": True}))
        bindings = {
            "_query_security_onion": lambda: SimpleNamespace(normalize=security),
            "_query_security_onion_policy": lambda: "policy",
            "_query_security_onion_dependencies": lambda: "dependencies",
            "InvestigationQueryError": ValueError,
        }
        context = {"permitted_observables": {"ips": ["192.0.2.10"]}}
        result = request_runtime_adapter.normalize_backend_parameters(
            bindings, "elastic", {"pack": "dns"}, "purpose", "window", context,
        )
        self.assertEqual(result, ({"pack": "dns"}, {"bound": True}))
        self.assertIs(security.call_args.kwargs["authorization_context"], context)
        self.assertEqual(security.call_args.kwargs["backend"], "elastic")

    def test_normalize_request_resolves_live_parameter_delegate(self) -> None:
        normalize = mock.Mock(return_value={"query_id": "q-1"})
        module = SimpleNamespace(
            Dependencies=lambda **values: SimpleNamespace(**values),
            normalize=normalize,
        )
        parameter_normalizer = mock.Mock()
        bindings = {
            "_query_request": lambda: module,
            "_query_request_policy": lambda: "policy",
            "_normalize_investigation_backend_parameters": parameter_normalizer,
            "InvestigationQueryError": ValueError,
        }
        context = {"case_id": "one"}
        result = request_runtime_adapter.normalize_request(
            bindings, {"backend": "elastic"}, round_number=2, position=3,
            time_envelope={"start": "a", "end": "b"},
            authorization_context=context,
        )
        self.assertEqual(result, {"query_id": "q-1"})
        self.assertIs(
            normalize.call_args.kwargs["dependencies"].normalize_parameters,
            parameter_normalizer,
        )
        self.assertIs(normalize.call_args.kwargs["authorization_context"], context)


if __name__ == "__main__":
    unittest.main()
