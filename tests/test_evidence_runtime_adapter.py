#!/usr/bin/env python3
"""Characterization tests for model-visible evidence runtime binding."""
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

from onion_sentinel.analysis.evidence import runtime_adapter


class EvidenceRuntimeAdapterTests(unittest.TestCase):
    def test_asset_owner_alias_requires_per_asset_hosted_opt_in(self) -> None:
        source = {"matched_assets": [
            {"asset_id": "private", "owner_ref": "operator-private"},
            {"asset_id": "shared", "owner_ref": "approved", "share_with_hosted_models": True},
            "malformed-preserved",
        ]}
        result = runtime_adapter.redact_unshared_asset_owners(source)
        self.assertNotIn("owner_ref", result["matched_assets"][0])
        self.assertEqual(result["matched_assets"][1]["owner_ref"], "approved")
        self.assertEqual(result["matched_assets"][2], "malformed-preserved")
        self.assertEqual(source["matched_assets"][0]["owner_ref"], "operator-private")

    def test_transport_policy_preserves_exact_disclosure_sets_and_sentinel(self) -> None:
        sentinel = object()
        module = SimpleNamespace(
            Policy=lambda **values: SimpleNamespace(**values))
        policy = runtime_adapter.transport_policy({
            "_evidence_transport": lambda: module,
            "MODEL_INTERNAL_KEYS": {"analysis_dir", "tool_paths"},
            "HOSTED_FORBIDDEN_KEYS": {"payload", "raw_rule"},
            "_MODEL_LIST_PATH_SENTINEL": sentinel,
            "HOSTED_TRANSPORT_FIXED_POINT_MAX_PASSES": 8,
        })
        self.assertEqual(policy.internal_keys, frozenset({"analysis_dir", "tool_paths"}))
        self.assertEqual(policy.hosted_forbidden_keys, frozenset({"payload", "raw_rule"}))
        self.assertIs(policy.list_path_sentinel, sentinel)
        self.assertEqual(policy.fixed_point_max_passes, 8)

    def test_registry_binds_live_reference_and_count_ports(self) -> None:
        class Registry:
            def __init__(self, **values):
                self.__dict__.update(values)

        class Dependencies:
            def __init__(self, **values):
                self.__dict__.update(values)

        bounded, source_class, count = mock.Mock(), mock.Mock(), mock.Mock()
        registry = runtime_adapter.registry_instance({
            "_evidence_registry": lambda: SimpleNamespace(
                Registry=Registry, Dependencies=Dependencies),
            "EVIDENCE_REFERENCE_MAX": 400,
            "_bounded_reference": bounded,
            "evidence_source_class": source_class,
            "_canonical_investigation_count": count,
        })
        self.assertEqual(registry.maximum_references, 400)
        self.assertIs(registry.deps.bounded_reference, bounded)
        self.assertIs(registry.deps.source_class, source_class)
        self.assertIs(registry.deps.canonical_count, count)

    def test_hosted_contract_uses_bounded_fixed_point_and_validation_error(self) -> None:
        synchronize = mock.Mock(return_value={"ready": True})
        module = SimpleNamespace(
            SynchronizationDependencies=lambda **values: SimpleNamespace(**values),
            synchronize_hosted_contract=synchronize,
        )
        package = {"case": "one"}
        safe_copy = mock.Mock()
        result = runtime_adapter.synchronize_hosted_contract({
            "_evidence_transport": lambda: module,
            "HOSTED_TRANSPORT_FIXED_POINT_MAX_PASSES": 8,
            "model_safe_copy": safe_copy,
            "_investigation_prompt_json_bytes": bytes,
            "InvestigationQueryError": ValueError,
        }, package)
        self.assertEqual(result, {"ready": True})
        self.assertIs(synchronize.call_args.args[0], package)
        self.assertEqual(synchronize.call_args.kwargs["maximum_passes"], 8)
        deps = synchronize.call_args.kwargs["dependencies"]
        deps.model_safe_copy({"x": 1})
        safe_copy.assert_called_once_with({"x": 1}, hosted=True)
        self.assertIs(deps.validation_error, ValueError)


if __name__ == "__main__":
    unittest.main()
