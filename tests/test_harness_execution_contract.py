#!/usr/bin/env python3
"""Specify the immutable execution identity required for every harness job."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

import harness_execution_contract as CONTRACT  # noqa: E402


class HarnessExecutionContractTests(unittest.TestCase):
    def skill_attestation(self) -> dict[str, object]:
        return {
            "registry_version": 7,
            "registry_sha256": "a" * 64,
            "selected": [
                {
                    "id": "z-skill",
                    "version": 2,
                    "skill_sha256": "c" * 64,
                    "guidance": "must never enter the execution contract",
                },
                {
                    "id": "a-skill",
                    "version": 1,
                    "skill_sha256": "b" * 64,
                },
            ],
            "selected_count": 2,
            "truncated": False,
            "advisory_mode": "advisory_only",
        }

    def test_contract_pins_exact_native_execution_identity(self) -> None:
        value = CONTRACT.build_execution_contract(
            source_revision="1" * 40,
            assigned_route="codex-cli:gpt-5.6-sol:high",
            reviewer_route="ollama:gemma4:26b-mlx",
            policy_version="2026-08-14",
            skill_attestation=self.skill_attestation(),
        )
        self.assertEqual(
            value,
            {
                "schema": "onion-sentinel-harness-execution-contract-v1",
                "source_revision": "1" * 40,
                "harness_version": "onion-sentinel-investigation-harness-v1",
                "policy_version": "2026-08-14",
                "primary": {
                    "route": "codex-cli:gpt-5.6-sol:high",
                    "provider": "codex-cli",
                    "model": "gpt-5.6-sol",
                    "reasoning_level": "high",
                },
                "reviewer": {
                    "route": "ollama:gemma4:26b-mlx",
                    "provider": "ollama",
                    "model": "gemma4:26b-mlx",
                    "reasoning_level": "not-applicable",
                },
                "skill_registry": {
                    "version": 7,
                    "sha256": "a" * 64,
                },
                "skill_versions": [
                    {
                        "id": "a-skill",
                        "version": 1,
                        "sha256": "b" * 64,
                    },
                    {
                        "id": "z-skill",
                        "version": 2,
                        "sha256": "c" * 64,
                    },
                ],
            },
        )
        self.assertEqual(CONTRACT.validate_execution_contract(value), value)
        self.assertEqual(len(CONTRACT.execution_contract_digest(value)), 64)

    def test_absent_reviewer_is_pinned_as_null(self) -> None:
        value = CONTRACT.build_execution_contract(
            source_revision="2" * 40,
            assigned_route="ollama:qwen3:30b-a3b",
            reviewer_route="",
            policy_version="v4",
            skill_attestation={
                "registry_version": 0,
                "registry_sha256": "",
                "selected": [],
                "selected_count": 0,
                "truncated": False,
                "advisory_mode": "unavailable",
            },
        )
        self.assertIsNone(value["reviewer"])
        self.assertEqual(value["primary"]["reasoning_level"], "not-applicable")

    def test_incomplete_or_external_identity_fails_closed(self) -> None:
        base = {
            "source_revision": "3" * 40,
            "assigned_route": "codex-cli:gpt-5.6-sol:high",
            "reviewer_route": "",
            "policy_version": "v4",
            "skill_attestation": self.skill_attestation(),
        }
        cases = (
            ({"source_revision": "main"}, "source revision"),
            ({"assigned_route": "codex-cli"}, "exact provider, model, and reasoning"),
            ({"assigned_route": "hermes-agent:gpt-5.6-sol:medium"}, "external harness provider"),
            ({"reviewer_route": "openclaw:ollama/gemma4:26b-mlx:high"}, "external harness provider"),
            ({"policy_version": ""}, "policy version"),
        )
        for overrides, message in cases:
            with self.subTest(overrides=overrides), self.assertRaisesRegex(
                ValueError,
                message,
            ):
                CONTRACT.build_execution_contract(**{**base, **overrides})

    def test_validation_rejects_mutable_or_unknown_contract_shape(self) -> None:
        value = CONTRACT.build_execution_contract(
            source_revision="4" * 40,
            assigned_route="codex-cli:gpt-5.6-terra:xhigh",
            reviewer_route="",
            policy_version="v4",
            skill_attestation=self.skill_attestation(),
        )
        cases = (
            ({**value, "future": True}, "field set"),
            ({**value, "schema": "future-v9"}, "schema"),
            ({**value, "source_revision": "5" * 39}, "source revision"),
            ({**value, "skill_versions": [{"id": "x"}]}, "skill version"),
        )
        for candidate, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                ValueError,
                message,
            ):
                CONTRACT.validate_execution_contract(candidate)

    def test_v2_contract_pins_explainable_selection_and_native_provider(self) -> None:
        attestation = {
            "framework_version": 2,
            "registry_version": 8,
            "registry_sha256": "a" * 64,
            "provider": "codex-cli",
            "provider_compatible": True,
            "selected": [
                {
                    "id": "dns-triage",
                    "version": "2.3.1",
                    "skill_sha256": "b" * 64,
                    "selection_reason": "exact_match_capability_and_promotion_gates_satisfied",
                },
            ],
            "selected_count": 1,
            "truncated": False,
            "rejected": [
                {"id": "legacy-dns", "reason": "artifact_revoked"},
            ],
            "aggregate_budget": {
                "max_queries": 4,
                "max_rows": 400,
                "max_bytes": 4000,
                "timeout_seconds": 40,
            },
            "advisory_mode": "identity_only_no_execution",
        }
        value = CONTRACT.build_execution_contract(
            source_revision="5" * 40,
            assigned_route="codex-cli:gpt-5.6-sol:high",
            reviewer_route="",
            policy_version="v5",
            skill_attestation=attestation,
        )
        self.assertEqual(
            value["schema"],
            "onion-sentinel-harness-execution-contract-v2",
        )
        self.assertEqual(
            value["skill_versions"],
            [{
                "id": "dns-triage",
                "version": "2.3.1",
                "sha256": "b" * 64,
                "selection_reason": "exact_match_capability_and_promotion_gates_satisfied",
            }],
        )
        self.assertEqual(
            value["skill_selection"],
            {
                "provider": "codex-cli",
                "provider_compatible": True,
                "selected_count": 1,
                "truncated": False,
                "rejected": [
                    {"id": "legacy-dns", "reason": "artifact_revoked"},
                ],
                "aggregate_budget": {
                    "max_queries": 4,
                    "max_rows": 400,
                    "max_bytes": 4000,
                    "timeout_seconds": 40,
                },
                "enforcement": "identity_only_no_execution",
            },
        )
        self.assertEqual(CONTRACT.validate_execution_contract(value), value)

        incompatible = dict(attestation)
        incompatible.update({"provider": "openclaw", "provider_compatible": False})
        with self.assertRaisesRegex(ValueError, "compatible native provider"):
            CONTRACT.build_execution_contract(
                source_revision="5" * 40,
                assigned_route="codex-cli:gpt-5.6-sol:high",
                reviewer_route="",
                policy_version="v5",
                skill_attestation=incompatible,
            )


if __name__ == "__main__":
    unittest.main()
