"""Contracts for the durable v2 investigation-skill registry lifecycle."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

SKILLS_SPEC = importlib.util.spec_from_file_location(
    "arr18_registry_skills", BIN / "investigation_skills_v2.py"
)
skills = importlib.util.module_from_spec(SKILLS_SPEC)
assert SKILLS_SPEC.loader is not None
SKILLS_SPEC.loader.exec_module(skills)

REGISTRY_SPEC = importlib.util.spec_from_file_location(
    "arr18_registry", BIN / "investigation_skill_registry_v2.py"
)
registry = importlib.util.module_from_spec(REGISTRY_SPEC)
assert REGISTRY_SPEC.loader is not None
REGISTRY_SPEC.loader.exec_module(registry)

CANDIDATE = (
    ROOT
    / "n8n/config/investigation-skills-v2-candidates/dns-triage-v2.candidate.json"
)


def manifest(identifier: str) -> dict[str, object]:
    value = json.loads(CANDIDATE.read_text(encoding="utf-8"))
    value["id"] = identifier
    value["version"] = "2.0.0"
    value["maintainer"]["reviewer"] = "independent-reviewer"
    value["verification"] = {
        "unit_tests": True,
        "replay_cases": 5,
        "independent_query_review": True,
        "adversarial_tests": True,
        "human_approved": True,
    }
    value["artifact_digest"] = skills.artifact_digest(value)
    return value


def record(
    value: dict[str, object], *, state: str = "active",
    dependencies: list[str] | None = None,
    conflicts: list[str] | None = None,
) -> dict[str, object]:
    return {
        "state": state,
        "manifest": value,
        "dependencies": dependencies or [],
        "conflicts": conflicts or [],
    }


def signer(payload: bytes) -> dict[str, str]:
    return {
        "algorithm": "external-ed25519",
        "key_id": "operator-release-key",
        "value": hashlib.sha512(payload).hexdigest(),
    }


def verifier(payload: bytes, signature: dict[str, str]) -> bool:
    return (
        signature["algorithm"] == "external-ed25519"
        and signature["key_id"] == "operator-release-key"
        and signature["value"] == hashlib.sha512(payload).hexdigest()
    )


def snapshot(
    records: list[dict[str, object]], *, revision: int = 1,
    mode: str = "active", previous: str = "",
) -> dict[str, object]:
    return registry.seal_registry({
        "schema": registry.SCHEMA,
        "revision": revision,
        "mode": mode,
        "provider_scope": "native-harness-only",
        "previous_registry_digest": previous,
        "revoked_artifact_digests": [],
        "records": records,
    }, signer=signer if mode == "active" else None)


def context() -> dict[str, str]:
    return {
        "task": "alert-triage",
        "protocol": "dns",
        "alert_family": "dns",
        "data_source": "elastic",
    }


class InvestigationSkillRegistryV2Tests(unittest.TestCase):
    def test_signed_active_snapshot_validates_without_mutation(self) -> None:
        value = snapshot([record(manifest("network.dns.primary"))])
        before = copy.deepcopy(value)

        validated = registry.validate_registry(value, verifier=verifier)

        self.assertEqual(value, before)
        self.assertEqual(validated, value)
        self.assertIsNot(validated, value)
        self.assertEqual(len(validated["registry_digest"]), 64)
        self.assertEqual(validated["signature"]["algorithm"], "external-ed25519")

    def test_active_snapshot_rejects_tamper_and_unverified_signature(self) -> None:
        value = snapshot([record(manifest("network.dns.primary"))])
        tampered = copy.deepcopy(value)
        tampered["revision"] = 2

        with self.assertRaisesRegex(ValueError, "registry digest mismatch"):
            registry.validate_registry(tampered, verifier=verifier)
        with self.assertRaisesRegex(ValueError, "registry signature verification failed"):
            registry.validate_registry(value, verifier=lambda payload, signature: False)
        with self.assertRaisesRegex(ValueError, "active registry requires signature verifier"):
            registry.validate_registry(value)

    def test_dependency_resolution_and_aggregate_budgets_are_explicit(self) -> None:
        dependency = manifest("network.dns.dependency")
        primary = manifest("network.dns.primary")
        value = snapshot([
            record(primary, dependencies=[dependency["artifact_digest"]]),
            record(dependency),
        ])

        selected = registry.select_registry(
            value,
            context(),
            "soc-analyst",
            primary["capabilities"],
            provider="codex-cli",
            budget={
                "max_queries": 24,
                "max_rows": 10000,
                "max_bytes": 16 * 1024 * 1024,
                "timeout_seconds": 600,
            },
            verifier=verifier,
        )

        self.assertTrue(selected["provider_compatible"])
        self.assertEqual(selected["registry_digest"], value["registry_digest"])
        self.assertEqual(
            [item["id"] for item in selected["selected"]],
            ["network.dns.dependency", "network.dns.primary"],
        )
        self.assertEqual(
            selected["aggregate_budget"],
            {
                "max_queries": 24,
                "max_rows": 10000,
                "max_bytes": 16 * 1024 * 1024,
                "timeout_seconds": 600,
            },
        )

        denied = registry.select_registry(
            value,
            context(),
            "soc-analyst",
            primary["capabilities"],
            provider="codex-cli",
            budget={
                "max_queries": 23,
                "max_rows": 10000,
                "max_bytes": 16 * 1024 * 1024,
                "timeout_seconds": 600,
            },
            verifier=verifier,
        )
        self.assertEqual(denied["selected"], [])
        self.assertEqual(
            {item["reason"] for item in denied["rejected"]},
            {"aggregate_budget_exceeded"},
        )

    def test_conflicts_revocations_and_external_providers_fail_visibly(self) -> None:
        first = manifest("network.dns.first")
        second = manifest("network.dns.second")
        conflicted = snapshot([
            record(first, conflicts=[second["artifact_digest"]]),
            record(second, conflicts=[first["artifact_digest"]]),
        ])
        kwargs = {
            "context": context(),
            "role": "soc-analyst",
            "permitted_capabilities": first["capabilities"],
            "budget": {
                "max_queries": 24,
                "max_rows": 10000,
                "max_bytes": 16 * 1024 * 1024,
                "timeout_seconds": 600,
            },
            "verifier": verifier,
        }

        conflict = registry.select_registry(
            conflicted, provider="ollama", **kwargs
        )
        self.assertEqual(conflict["selected"], [])
        self.assertEqual(
            {item["reason"] for item in conflict["rejected"]},
            {"skill_conflict"},
        )

        external = registry.select_registry(
            conflicted, provider="hermes-agent", **kwargs
        )
        self.assertFalse(external["provider_compatible"])
        self.assertEqual(external["selected"], [])
        self.assertEqual(
            {item["reason"] for item in external["rejected"]},
            {"unsupported_provider"},
        )

        revoked_raw = {
            "schema": registry.SCHEMA,
            "revision": 2,
            "mode": "active",
            "provider_scope": "native-harness-only",
            "previous_registry_digest": conflicted["registry_digest"],
            "revoked_artifact_digests": [first["artifact_digest"]],
            "records": [record(first, state="revoked")],
        }
        revoked = registry.seal_registry(revoked_raw, signer=signer)
        selected = registry.select_registry(
            revoked, provider="codex-cli", **kwargs
        )
        self.assertEqual(selected["selected"], [])
        self.assertEqual(selected["rejected"][0]["reason"], "artifact_revoked")

    def test_rollback_returns_exact_predecessor_snapshot(self) -> None:
        previous = snapshot([record(manifest("network.dns.previous"))])
        current = snapshot(
            [record(manifest("network.dns.current"))],
            revision=2,
            previous=previous["registry_digest"],
        )
        history = [current, previous]
        before = copy.deepcopy(history)

        restored = registry.rollback_snapshot(
            history,
            current["registry_digest"],
            verifier=verifier,
        )

        self.assertEqual(restored, previous)
        self.assertEqual(history, before)


if __name__ == "__main__":
    unittest.main()
