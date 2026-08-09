#!/usr/bin/env python3
"""Characterization tests for query prompt/planning runtime binding."""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
if str(N8N_ROOT) not in sys.path:
    sys.path.insert(0, str(N8N_ROOT))

from onion_sentinel.analysis.query import runtime_adapter


class QueryRuntimeAdapterTests(unittest.TestCase):
    def test_evidence_reference_component_is_stable_and_collision_resistant(self) -> None:
        bindings = {"_query_text": lambda value, limit: str(value)[:limit]}
        self.assertEqual(
            runtime_adapter.evidence_ref_component(bindings, "query:one"),
            "query:one",
        )
        first = runtime_adapter.evidence_ref_component(bindings, "unsafe value")
        second = runtime_adapter.evidence_ref_component(bindings, "unsafe value")
        self.assertEqual(first, second)
        self.assertRegex(first, r"^sha256-[0-9a-f]{20}$")

    def test_prompt_payload_preserves_exact_budget_policy_and_dependencies(self) -> None:
        build = mock.Mock(return_value={"schema": "result-v1"})
        module = SimpleNamespace(
            Policy=lambda **values: SimpleNamespace(**values),
            payload=build,
        )
        dependencies = object()
        result = runtime_adapter.prompt_payload({
            "_query_prompt_budget": lambda: module,
            "MAX_INVESTIGATION_PROMPT_EVIDENCE_ROWS": 80,
            "INVESTIGATION_QUERY_RESULT_SCHEMA": "result-v1",
            "_query_prompt_budget_dependencies": lambda: dependencies,
            "InvestigationQueryError": ValueError,
        }, [{"round": 1}], maximum_bytes=4096)
        self.assertEqual(result, {"schema": "result-v1"})
        self.assertEqual(build.call_args.kwargs["maximum_bytes"], 4096)
        self.assertEqual(build.call_args.kwargs["policy"].maximum_rows, 80)
        self.assertEqual(build.call_args.kwargs["policy"].result_schema, "result-v1")
        self.assertIs(build.call_args.kwargs["dependencies"], dependencies)

    def test_prompt_admission_preserves_hosted_and_total_byte_boundaries(self) -> None:
        admit = mock.Mock(return_value=2048)
        module = SimpleNamespace(
            Policy=lambda **values: SimpleNamespace(**values),
            admit=admit,
        )
        package: dict = {}
        result = runtime_adapter.admit_prompt({
            "_query_prompt_admission": lambda: module,
            "MAX_INVESTIGATION_PROMPT_EVIDENCE_BYTES": 1024,
            "_query_prompt_admission_dependencies": lambda: "dependencies",
            "InvestigationQueryError": ValueError,
        }, package, [{"round": 1}], maximum_prompt_bytes=8192, hosted=True)
        self.assertEqual(result, 2048)
        self.assertIs(admit.call_args.args[0], package)
        self.assertTrue(admit.call_args.kwargs["hosted"])
        self.assertEqual(admit.call_args.kwargs["maximum_prompt_bytes"], 8192)
        self.assertEqual(
            admit.call_args.kwargs["policy"].maximum_evidence_bytes, 1024)

    def test_repair_scope_retains_authorization_and_original_error_type(self) -> None:
        scope = mock.Mock(return_value={"query_id": "repair-1"})
        context = {"case_id": "one"}
        dependencies = object()
        result = runtime_adapter.repair_scope({
            "_query_repair": lambda: SimpleNamespace(scope=scope),
            "_query_repair_dependencies": lambda: dependencies,
            "InvestigationQueryError": ValueError,
        }, {"backend": "elastic"}, round_number=2, position=1,
            time_envelope={"start": "a", "end": "b"},
            authorization_context=context)
        self.assertEqual(result, {"query_id": "repair-1"})
        self.assertIs(scope.call_args.kwargs["authorization_context"], context)
        self.assertIs(scope.call_args.kwargs["dependencies"], dependencies)
        self.assertIs(scope.call_args.kwargs["error_type"], ValueError)

    def test_legacy_dependencies_bind_live_ports_and_query_id_contract(self) -> None:
        class Dependencies:
            def __init__(self, **values):
                self.__dict__.update(values)

        sentinel = lambda *_args, **_kwargs: None
        names = (
            "pop_investigation_query_requests",
            "deterministic_incident_pivot_requests", "model_safe_copy",
            "normalize_investigation_query_request",
            "validate_investigation_query_repair_scope",
            "investigation_backend_available",
            "investigation_request_semantic_digest",
            "live_osquery_harness_operator_approved", "query_backend_is_approval_gated",
            "policy_decision_is_effective", "query_backend_capability",
            "investigation_query_repair_scope", "_query_text",
            "investigation_query_repair_failures", "project_now",
            "_validated_discovered_observables", "investigation_query_canonical_digest",
            "canonical_payload_digest", "investigation_query_repair_prompt_entry",
            "investigation_query_request_from_repair_scope",
            "_admit_investigation_query_prompt", "investigation_query_outcome_summary",
            "_investigation_round_audit", "investigation_query_binding_summary",
            "_append_investigation_evidence_gaps",
        )
        bindings = {name: sentinel for name in names}
        bindings.update({
            "INVESTIGATION_QUERY_ID_RE": re.compile(r"q-[0-9]+"),
            "time": SimpleNamespace(monotonic=lambda: 1.0),
            "sys": SimpleNamespace(stderr=sys.stderr),
        })
        dependencies = runtime_adapter.legacy_dependencies(
            bindings, SimpleNamespace(Dependencies=Dependencies))
        self.assertIs(dependencies.pop_requests, sentinel)
        self.assertTrue(dependencies.valid_query_id("q-12"))
        self.assertFalse(dependencies.valid_query_id("invalid"))
        self.assertEqual(dependencies.monotonic(), 1.0)


if __name__ == "__main__":
    unittest.main()
