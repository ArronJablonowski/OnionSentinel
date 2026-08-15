from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "operations/cross_host_handoff_contract.py"
CLI_PATH = ROOT / "operations/validate-cross-host-handoff.py"
SPEC = importlib.util.spec_from_file_location("cross_host_handoff_contract", MODULE_PATH)
assert SPEC and SPEC.loader
handoff = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = handoff
SPEC.loader.exec_module(handoff)


class CrossHostHandoffContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name) / "repo"
        source = self.repo / "relay/app/relay.py"
        source.parent.mkdir(parents=True)
        source.write_text("print('relay')\n", encoding="utf-8")
        subprocess.run(("git", "init", "-q"), cwd=self.repo, check=True)
        subprocess.run(
            ("git", "config", "user.email", "test@example.invalid"),
            cwd=self.repo,
            check=True,
        )
        subprocess.run(
            ("git", "config", "user.name", "Test"), cwd=self.repo, check=True
        )
        subprocess.run(("git", "add", "."), cwd=self.repo, check=True)
        subprocess.run(("git", "commit", "-qm", "fixture"), cwd=self.repo, check=True)
        self.revision = subprocess.check_output(
            ("git", "rev-parse", "HEAD"), cwd=self.repo, text=True
        ).strip()
        self.source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
        self.document = {
            "schema_version": 1,
            "change_id": "ARR-35-relay-001",
            "request": {
                "target_system": "relay",
                "owner": "relay-operator",
                "purpose": "Deploy the reviewed Relay application payload.",
                "prerequisites": ["A maintenance window is active."],
                "risk": "medium",
                "validation": ["Run the bounded Relay readiness check."],
                "rollback": ["Reinstall the recorded rollback revision."],
                "write_authorized": True,
                "authorized_operations": [
                    "replace_managed_artifact",
                    "reload_managed_service",
                ],
                "source_revision": self.revision,
                "rollback_revision": self.revision,
                "requested_at": "2026-08-15T04:00:00Z",
                "artifacts": [
                    {
                        "source": "relay/app/relay.py",
                        "destination": "/opt/so-alert-relay/app/relay.py",
                        "sha256": self.source_sha,
                        "expected_current_sha256": "d" * 64,
                        "observed_current_sha256": "d" * 64,
                    }
                ],
            },
            "acknowledgement": None,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_pending_authorized_request_is_actionable_and_deterministic(self) -> None:
        first = handoff.build_handoff_plan(self.repo, self.document)
        second = handoff.build_handoff_plan(self.repo, self.document)
        self.assertEqual(first, second)
        self.assertEqual(first["decision"], "apply_authorized")
        self.assertFalse(first["idempotent_replay"])
        self.assertRegex(first["request_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(first["artifact_counts"], {"desired": 1, "drifted": 0})
        self.assertNotIn("purpose", first)
        self.assertNotIn("prerequisites", first)

    def test_security_onion_request_requires_separate_write_authorization(self) -> None:
        document = copy.deepcopy(self.document)
        document["change_id"] = "ARR-35-security-onion-001"
        request = document["request"]
        request["target_system"] = "security_onion"
        request["write_authorized"] = False
        request["authorized_operations"] = []
        request["artifacts"] = []
        plan = handoff.build_handoff_plan(self.repo, document)
        self.assertEqual(plan["decision"], "approval_required")

    def test_applied_acknowledgement_binds_hashes_and_becomes_noop(self) -> None:
        document = copy.deepcopy(self.document)
        digest = handoff.request_digest(document)
        document["acknowledgement"] = {
            "status": "applied",
            "request_sha256": digest,
            "applied_version": self.revision,
            "applied_at": "2026-08-15T04:10:00Z",
            "rollback_point": self.revision,
            "artifacts": [
                {
                    "destination": "/opt/so-alert-relay/app/relay.py",
                    "sha256": self.source_sha,
                }
            ],
            "verification": [
                {
                    "check": "relay_readiness",
                    "status": "pass",
                    "evidence_sha256": "a" * 64,
                }
            ],
        }
        plan = handoff.build_handoff_plan(self.repo, document)
        self.assertEqual(plan["decision"], "noop_already_applied")
        self.assertEqual(plan["artifact_counts"], {"desired": 1, "drifted": 0})

    def test_applied_receipt_drift_requires_review_and_never_reapplies(self) -> None:
        document = copy.deepcopy(self.document)
        digest = handoff.request_digest(document)
        document["acknowledgement"] = {
            "status": "applied",
            "request_sha256": digest,
            "applied_version": self.revision,
            "applied_at": "2026-08-15T04:10:00Z",
            "rollback_point": self.revision,
            "artifacts": [
                {
                    "destination": "/opt/so-alert-relay/app/relay.py",
                    "sha256": "b" * 64,
                }
            ],
            "verification": [
                {
                    "check": "relay_readiness",
                    "status": "pass",
                    "evidence_sha256": "a" * 64,
                }
            ],
        }
        plan = handoff.build_handoff_plan(self.repo, document)
        self.assertEqual(plan["decision"], "drift_review_required")
        self.assertEqual(plan["artifact_counts"], {"desired": 1, "drifted": 1})

    def test_failed_verification_cannot_be_reported_as_already_applied(self) -> None:
        document = copy.deepcopy(self.document)
        digest = handoff.request_digest(document)
        document["acknowledgement"] = {
            "status": "applied",
            "request_sha256": digest,
            "applied_version": self.revision,
            "applied_at": "2026-08-15T04:10:00Z",
            "rollback_point": self.revision,
            "artifacts": [
                {
                    "destination": "/opt/so-alert-relay/app/relay.py",
                    "sha256": self.source_sha,
                }
            ],
            "verification": [
                {
                    "check": "relay_readiness",
                    "status": "fail",
                    "evidence_sha256": "a" * 64,
                }
            ],
        }
        plan = handoff.build_handoff_plan(self.repo, document)
        self.assertEqual(plan["decision"], "verification_review_required")

    def test_acknowledgement_cannot_claim_an_unauthorized_write(self) -> None:
        document = copy.deepcopy(self.document)
        document["request"]["write_authorized"] = False
        document["request"]["authorized_operations"] = []
        digest = handoff.request_digest(document)
        document["acknowledgement"] = {
            "status": "applied",
            "request_sha256": digest,
            "applied_version": self.revision,
            "applied_at": "2026-08-15T04:10:00Z",
            "rollback_point": self.revision,
            "artifacts": [],
            "verification": [
                {
                    "check": "relay_readiness",
                    "status": "pass",
                    "evidence_sha256": "a" * 64,
                }
            ],
        }
        with self.assertRaisesRegex(handoff.HandoffError, "without write authorization"):
            handoff.build_handoff_plan(self.repo, document)

    def test_acknowledgement_must_preserve_the_recorded_rollback_point(self) -> None:
        document = copy.deepcopy(self.document)
        digest = handoff.request_digest(document)
        document["acknowledgement"] = {
            "status": "applied",
            "request_sha256": digest,
            "applied_version": self.revision,
            "applied_at": "2026-08-15T04:10:00Z",
            "rollback_point": "d" * 40,
            "artifacts": [
                {
                    "destination": "/opt/so-alert-relay/app/relay.py",
                    "sha256": self.source_sha,
                }
            ],
            "verification": [
                {
                    "check": "relay_readiness",
                    "status": "pass",
                    "evidence_sha256": "a" * 64,
                }
            ],
        }
        with self.assertRaisesRegex(handoff.HandoffError, "rollback point"):
            handoff.build_handoff_plan(self.repo, document)

    def test_exact_prior_request_is_idempotent_but_identity_collision_fails(self) -> None:
        plan = handoff.build_handoff_plan(
            self.repo, self.document, prior_document=copy.deepcopy(self.document)
        )
        self.assertTrue(plan["idempotent_replay"])
        changed = copy.deepcopy(self.document)
        changed["request"]["purpose"] = "Different purpose under the same identity."
        with self.assertRaisesRegex(handoff.HandoffError, "identity collision"):
            handoff.build_handoff_plan(
                self.repo, changed, prior_document=self.document
            )

    def test_source_manifest_drift_fails_before_any_apply_decision(self) -> None:
        document = copy.deepcopy(self.document)
        document["request"]["artifacts"][0]["sha256"] = "c" * 64
        with self.assertRaisesRegex(handoff.HandoffError, "source artifact hash"):
            handoff.build_handoff_plan(self.repo, document)

    def test_predeployment_observation_drift_stops_before_apply(self) -> None:
        document = copy.deepcopy(self.document)
        document["request"]["artifacts"][0]["observed_current_sha256"] = "e" * 64
        plan = handoff.build_handoff_plan(self.repo, document)
        self.assertEqual(plan["decision"], "drift_review_required")
        self.assertEqual(plan["artifact_counts"], {"desired": 1, "drifted": 1})

    def test_already_current_predeployment_observation_is_a_noop(self) -> None:
        document = copy.deepcopy(self.document)
        artifact = document["request"]["artifacts"][0]
        artifact["expected_current_sha256"] = self.source_sha
        artifact["observed_current_sha256"] = self.source_sha
        plan = handoff.build_handoff_plan(self.repo, document)
        self.assertEqual(plan["decision"], "noop_current_match")

    def test_secret_like_handoff_content_and_private_key_paths_are_rejected(self) -> None:
        for field, value in (
            ("purpose", "Set TELEGRAM_BOT_" + "TOKEN=" + "secret-value"),
            ("purpose", "Paste the -----BEGIN OPENSSH PRIVATE" + " KEY----- block."),
        ):
            document = copy.deepcopy(self.document)
            document["request"][field] = value
            with self.subTest(value=value):
                with self.assertRaisesRegex(handoff.HandoffError, "sensitive"):
                    handoff.build_handoff_plan(self.repo, document)
        document = copy.deepcopy(self.document)
        document["request"]["artifacts"][0]["source"] = "relay/keys/private.key"
        with self.assertRaisesRegex(handoff.HandoffError, "private key"):
            handoff.build_handoff_plan(self.repo, document)

    def test_unknown_fields_and_unsafe_paths_fail_closed(self) -> None:
        document = copy.deepcopy(self.document)
        document["request"]["unexpected"] = True
        with self.assertRaisesRegex(handoff.HandoffError, "unknown field"):
            handoff.build_handoff_plan(self.repo, document)
        document = copy.deepcopy(self.document)
        document["request"]["artifacts"][0]["source"] = "../relay.py"
        with self.assertRaisesRegex(handoff.HandoffError, "source path"):
            handoff.build_handoff_plan(self.repo, document)

    def test_live_configuration_destinations_cannot_be_overwritten(self) -> None:
        document = copy.deepcopy(self.document)
        document["request"]["artifacts"][0]["destination"] = (
            "/etc/so-alert-relay/relay.env"
        )
        with self.assertRaisesRegex(handoff.HandoffError, "runtime configuration"):
            handoff.build_handoff_plan(self.repo, document)

    def test_plan_projection_is_metadata_only(self) -> None:
        plan = handoff.build_handoff_plan(self.repo, self.document)
        encoded = json.dumps(plan, sort_keys=True)
        self.assertNotIn("Relay application payload", encoded)
        self.assertNotIn("maintenance window", encoded)
        self.assertNotIn("/opt/so-alert-relay", encoded)

    def test_cli_emits_only_the_plan_and_has_stable_exit_codes(self) -> None:
        handoff_path = Path(self.temporary.name) / "handoff.json"
        handoff_path.write_text(json.dumps(self.document), encoding="utf-8")
        completed = subprocess.run(
            (
                sys.executable,
                str(CLI_PATH),
                "--repo-root",
                str(self.repo),
                "--handoff",
                str(handoff_path),
            ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["decision"], "apply_authorized")
        self.assertEqual(completed.stderr, "")

        unauthorized = copy.deepcopy(self.document)
        unauthorized["request"]["write_authorized"] = False
        unauthorized["request"]["authorized_operations"] = []
        handoff_path.write_text(json.dumps(unauthorized), encoding="utf-8")
        completed = subprocess.run(
            (
                sys.executable,
                str(CLI_PATH),
                "--repo-root",
                str(self.repo),
                "--handoff",
                str(handoff_path),
            ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(json.loads(completed.stdout)["decision"], "approval_required")

    def test_cli_rejects_duplicate_json_keys_and_symlinked_handoffs(self) -> None:
        handoff_path = Path(self.temporary.name) / "handoff.json"
        handoff_path.write_text('{"schema_version":1,"schema_version":1}\n')
        base = (
            sys.executable,
            str(CLI_PATH),
            "--repo-root",
            str(self.repo),
            "--handoff",
        )
        completed = subprocess.run(
            (*base, str(handoff_path)),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["ok"], False)
        self.assertNotIn("schema_version", json.loads(completed.stdout)["error"])
        link = Path(self.temporary.name) / "handoff-link.json"
        link.symlink_to(handoff_path)
        completed = subprocess.run(
            (*base, str(link)),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("safe regular file", json.loads(completed.stdout)["error"])

    def test_repository_example_is_valid_and_explicitly_read_only(self) -> None:
        example = json.loads(
            (ROOT / "operations/security/cross-host-change.example.json").read_text(
                encoding="utf-8"
            )
        )
        plan = handoff.build_handoff_plan(ROOT, example)
        self.assertEqual(plan["decision"], "approval_required")
        self.assertEqual(plan["target_system"], "relay")


if __name__ == "__main__":
    unittest.main()
