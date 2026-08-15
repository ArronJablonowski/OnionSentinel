#!/usr/bin/env python3
"""Acceptance tests for the disabled endpoint-response governance boundary."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "operations" / "validate-endpoint-response-governance.py"
CONTRACT = ROOT / "operations" / "security" / "endpoint-response-governance.json"


def load_validator():
    spec = importlib.util.spec_from_file_location("endpoint_response_governance", VALIDATOR)
    if spec is None or spec.loader is None:
        raise AssertionError("endpoint-response governance validator is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def cloned_contract() -> dict[str, object]:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


class EndpointResponseGovernanceTests(unittest.TestCase):
    maxDiff = None

    def test_repository_contract_is_valid_and_inert(self) -> None:
        module = load_validator()
        contract = module.load_contract(CONTRACT)
        result = module.validate_contract(contract, ROOT)
        self.assertEqual(result["errors"], [])
        self.assertEqual(contract["schema"], "onion-sentinel-endpoint-response-governance-v1")
        self.assertEqual(contract["status"], "disabled")
        self.assertFalse(contract["review_gates"]["security_review_approved"])
        self.assertFalse(contract["review_gates"]["guarded_poc_approved"])
        self.assertFalse(contract["execution_policy"]["enabled"])

    def test_read_and_mutation_authority_are_separate(self) -> None:
        contract = cloned_contract()
        tiers = contract["capability_tiers"]
        self.assertEqual(set(tiers), {"investigation_read_only", "response_mutation"})
        read_tier = tiers["investigation_read_only"]
        mutation_tier = tiers["response_mutation"]
        self.assertNotEqual(read_tier["broker_identity"], mutation_tier["broker_identity"])
        self.assertNotEqual(read_tier["credential_scope"], mutation_tier["credential_scope"])
        self.assertNotEqual(read_tier["route_scope"], mutation_tier["route_scope"])
        self.assertFalse(read_tier["state_change_allowed"])
        self.assertTrue(mutation_tier["state_change_allowed"])
        self.assertFalse(mutation_tier["enabled"])

    def test_models_can_only_recommend_and_humans_approve(self) -> None:
        contract = cloned_contract()
        principals = {item["id"]: item for item in contract["principals"]}
        self.assertFalse(principals["model_recommender"]["can_approve"])
        self.assertFalse(principals["model_recommender"]["can_execute"])
        self.assertEqual(principals["model_recommender"]["authority"], "recommend_only")
        approval = contract["approval_policy"]
        self.assertEqual(approval["minimum_distinct_human_approvers"], 2)
        self.assertFalse(approval["model_identity_may_approve"])
        self.assertFalse(approval["free_text_is_authorization"])
        self.assertEqual(
            set(approval["digest_binding_fields"]),
            {"request_id", "action_id", "target_asset_id", "parameters_sha256", "expires_at"},
        )

    def test_candidate_actions_are_typed_bounded_and_reversible(self) -> None:
        contract = cloned_contract()
        actions = contract["action_catalog"]
        self.assertEqual([action["id"] for action in actions], ["endpoint_network_isolation"])
        for action in actions:
            self.assertEqual(action["capability_tier"], "response_mutation")
            self.assertTrue(action["reversible"])
            self.assertTrue(action["rollback_action_id"])
            self.assertLessEqual(action["maximum_timeout_seconds"], 120)
            self.assertNotIn("command", action)
            self.assertNotIn("transport", action)

    def test_required_threats_have_fail_closed_controls(self) -> None:
        contract = cloned_contract()
        threats = {item["id"]: item for item in contract["threat_model"]}
        self.assertEqual(
            set(threats),
            {
                "compromised_endpoint",
                "command_injection",
                "credential_theft",
                "lateral_movement",
                "evidence_tampering",
            },
        )
        for threat in threats.values():
            self.assertTrue(threat["controls"])
            self.assertTrue(threat["fail_closed_result"])

    def test_dangerous_widening_fails_closed(self) -> None:
        module = load_validator()
        mutations = {
            "premature enablement": ("execution_policy", "enabled", True),
            "interactive shell": ("execution_policy", "interactive_shell_allowed", True),
            "unrestricted SSH": ("execution_policy", "unrestricted_ssh_allowed", True),
            "arbitrary command": ("execution_policy", "arbitrary_command_allowed", True),
            "model approval": ("approval_policy", "model_identity_may_approve", True),
            "single approval": ("approval_policy", "minimum_distinct_human_approvers", 1),
            "model target selection": ("target_policy", "model_may_select_target", True),
            "wildcard target": ("target_policy", "wildcard_targets_allowed", True),
        }
        for label, (section, field, value) in mutations.items():
            with self.subTest(label=label):
                contract = cloned_contract()
                contract[section][field] = value
                result = module.validate_contract(contract, ROOT)
                self.assertTrue(result["errors"], result)

        contract = cloned_contract()
        contract["action_catalog"][0]["reversible"] = False
        contract["action_catalog"][0]["rollback_action_id"] = None
        result = module.validate_contract(contract, ROOT)
        self.assertTrue(result["errors"], result)

        contract = cloned_contract()
        widened = json.loads(json.dumps(contract["action_catalog"][0]))
        widened["id"] = "endpoint_reboot"
        widened["rollback_action_id"] = "endpoint_reboot_rollback"
        contract["action_catalog"].append(widened)
        result = module.validate_contract(contract, ROOT)
        self.assertTrue(result["errors"], result)

    def test_shared_broker_or_credential_scope_fails_closed(self) -> None:
        module = load_validator()
        for field in ("broker_identity", "credential_scope", "route_scope"):
            with self.subTest(field=field):
                contract = cloned_contract()
                tiers = contract["capability_tiers"]
                tiers["response_mutation"][field] = tiers["investigation_read_only"][field]
                result = module.validate_contract(contract, ROOT)
                self.assertTrue(result["errors"], result)

    def test_unknown_fields_and_secret_material_are_rejected(self) -> None:
        module = load_validator()
        contract = cloned_contract()
        contract["execution_policy"]["shell_command"] = "ssh root@example.invalid"
        result = module.validate_contract(contract, ROOT)
        self.assertTrue(result["errors"], result)

        contract = cloned_contract()
        contract["purpose"] = "token=not-a-real-secret-but-still-forbidden"
        result = module.validate_contract(contract, ROOT)
        self.assertTrue(result["errors"], result)

    def test_loader_is_bounded_and_cli_is_a_documented_release_gate(self) -> None:
        module = load_validator()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "oversized.json"
            path.write_bytes(b" " * (module.MAX_FILE_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "byte budget"):
                module.load_contract(path)

            duplicate = Path(temporary) / "duplicate.json"
            duplicate.write_text('{"schema":"first","schema":"second"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
                module.load_contract(duplicate)

        command = "python3 operations/validate-endpoint-response-governance.py"
        operations = (ROOT / "operations" / "README.md").read_text(encoding="utf-8")
        deployment = (ROOT / "docs" / "product-deployment-requirements.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(command, operations)
        self.assertIn(command, deployment)
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), "--contract", str(CONTRACT)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["status"], "disabled_contract_valid")
        self.assertEqual(payload["action_count"], 1)
        self.assertEqual(payload["threat_count"], 5)

    def test_invalid_diagnostics_are_deterministic(self) -> None:
        contract = cloned_contract()
        contract["status"] = "enabled"
        contract["approval_policy"]["minimum_distinct_human_approvers"] = 1
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid-contract.json"
            path.write_text(json.dumps(contract), encoding="utf-8")
            diagnostics = []
            for seed in ("1", "2", "8675309"):
                result = subprocess.run(
                    [sys.executable, str(VALIDATOR), "--contract", str(path)],
                    cwd=ROOT,
                    env={**os.environ, "PYTHONHASHSEED": seed},
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                diagnostics.append(json.loads(result.stdout)["errors"])
        self.assertEqual(diagnostics[1:], diagnostics[:1] * 2)


if __name__ == "__main__":
    unittest.main()
