#!/usr/bin/env python3
"""Tests for owner-only pre-dispatch cohort evidence sealing."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "operations"
if str(OPERATIONS) not in sys.path:
    sys.path.insert(0, str(OPERATIONS))

import cohort_evidence_sealing as sealing  # noqa: E402
from cohort_evaluation_adjudication_service import (  # noqa: E402
    AdjudicationSealService,
)
from cohort_manifest_adapters import (  # noqa: E402
    execution_contract,
    frozen_plan_digest,
    ordered_identity_projection,
)
from cohort_runner_contracts import sha256_value  # noqa: E402


CLI_PATH = OPERATIONS / "seal-independent-cohort-evidence.py"


def load_cli():
    spec = importlib.util.spec_from_file_location("cohort_seal_cli", CLI_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load evidence sealing CLI")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CohortEvidenceSealingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.ir_path = self.root / "ir-manifest.json"
        self.soc_path = self.root / "soc-manifest.json"
        self.draft_path = self.root / "ground-truth.json"
        self.methodology_path = self.root / "methodology.md"
        self.output_path = self.root / "evidence-seal.json"
        self.cli = load_cli()
        self._write_bytes(
            self.methodology_path,
            b"Independent read-only evidence review methodology v1\n",
        )
        self.manifests = {
            "incident-responder": self._manifest("incident-responder"),
            "soc-analyst": self._manifest("soc-analyst"),
        }
        self._write_json(self.ir_path, self.manifests["incident-responder"])
        self._write_json(self.soc_path, self.manifests["soc-analyst"])
        self._write_json(self.draft_path, self._draft())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_bytes(self, path: Path, value: bytes, mode: int = 0o600) -> None:
        path.write_bytes(value)
        path.chmod(mode)

    def _write_json(self, path: Path, value: dict, mode: int = 0o600) -> None:
        self._write_bytes(
            path,
            (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(),
            mode,
        )

    def _members(self, role: str) -> list[dict]:
        kind = "analyze" if role == "soc-analyst" else "escalate"
        return [
            {
                "rank": rank,
                "dashboard_group_id": f"{rank:012x}",
                "stable_group_id": f"{rank:020x}",
                "stable_group_key": f"stable-key-{rank}",
                "representative_alert_id": f"alert-{rank}",
                "detection": {
                    "stable_group_key": f"stable-key-{rank}",
                    "rule_name": f"rule-{rank}",
                },
                "pre_state": {},
                "dispatch": {
                    "kind": kind,
                    "state": "unattempted",
                    "attempt_count": 0,
                },
                "monitor": {"state": "not_started"},
            }
            for rank in range(1, 3)
        ]

    def _manifest(self, role: str) -> dict:
        members = self._members(role)
        identities = ordered_identity_projection(members)
        document = {
            "schema": "onion-sentinel-incident-harness-cohort-v4",
            "cohort_id": f"arr20-{role}",
            "reason": "ARR-20 matched independent cohort qualification",
            "agent_role": role,
            "count": 2,
            "created_at": "2026-08-14T20:00:00Z",
            "selection": {
                "mode": "imported_rows",
                "source_sha256": "a" * 64,
                "source_count": 2,
                "order_preserved": True,
                "ordered_identity_sha256": sha256_value(identities),
            },
            "execution_contract": execution_contract(
                expected_release_id="b" * 40,
                expected_assigned_route="codex-cli:gpt-5.5:high",
                expected_reviewer_route="codex-cli:gpt-5.6-sol:xhigh",
            ),
            "database": {
                "path": "/private/alerts.db",
                "schema_sha256": "c" * 64,
                "user_version": 1,
                "read_only": True,
            },
            "security_onion_access": "none",
            "state": "frozen",
            "members": members,
        }
        document["frozen_plan_sha256"] = frozen_plan_digest(document)
        document["manifest_sha256"] = sha256_value(document)
        return document

    def _ground_truth(self, member: dict) -> dict:
        return {
            "labels": {
                "detection_outcome": "true_positive_malicious",
                "event_status": "observed",
                "detection_validity": "matched_intent",
                "activity_disposition": "malicious",
                "handling": "contain",
                "duplicate_of": None,
            },
            "confidence": "high",
            "detection_sha256": sha256_value(member["detection"]),
            "evidence_basis_sha256": "d" * 64,
            "scope_timeline_sha256": "e" * 64,
            "attribution_sha256": "f" * 64,
            "required_query_classes": ["suricata", "network_flow"],
            "telemetry_gap_codes": [],
        }

    def _draft(self) -> dict:
        members = self.manifests["incident-responder"]["members"]
        document = {
            "schema": "onion-sentinel-independent-evidence-draft-v1",
            "experiment_id": "arr20-matched-unit",
            "expected_count": 2,
            "independent_review": True,
            "reviewer_count": 1,
            "cases": [
                {
                    "rank": member["rank"],
                    "stable_group_id": member["stable_group_id"],
                    "ground_truth": self._ground_truth(member),
                }
                for member in members
            ],
        }
        document["draft_sha256"] = sha256_value(document)
        return document

    def _args(self) -> list[str]:
        return [
            "--manifest", f"incident-responder={self.ir_path}",
            "--manifest", f"soc-analyst={self.soc_path}",
            "--ground-truth", str(self.draft_path),
            "--methodology", str(self.methodology_path),
            "--expected-count", "2",
            "--output", str(self.output_path),
        ]

    def _run(self) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = self.cli.main(self._args())
        return status, stdout.getvalue(), stderr.getvalue()

    def _resign_manifest(self, role: str, path: Path) -> None:
        document = self.manifests[role]
        document.pop("frozen_plan_sha256", None)
        document["frozen_plan_sha256"] = frozen_plan_digest(document)
        document.pop("manifest_sha256", None)
        document["manifest_sha256"] = sha256_value(document)
        self._write_json(path, document)

    def test_builds_owner_only_seal_bound_to_exact_pristine_role_plans(self) -> None:
        status, stdout, stderr = self._run()
        self.assertEqual((status, stderr), (0, ""))
        self.assertEqual(stat.S_IMODE(self.output_path.stat().st_mode), 0o600)
        seal = json.loads(self.output_path.read_text(encoding="utf-8"))
        self.assertEqual(seal["schema"], self.cli.EVIDENCE_SEAL_SCHEMA)
        self.assertEqual(seal["source_rows_sha256"], "a" * 64)
        self.assertEqual(set(seal["role_plans"]), {"incident-responder", "soc-analyst"})
        for role, manifest in self.manifests.items():
            self.assertEqual(
                seal["role_plans"][role],
                {
                    "cohort_id": manifest["cohort_id"],
                    "frozen_plan_sha256": manifest["frozen_plan_sha256"],
                },
            )
        self.assertEqual(seal["seal_sha256"], sha256_value({
            key: value for key, value in seal.items() if key != "seal_sha256"
        }))
        self.assertNotIn("ground_truth", stdout)
        self.assertNotIn("methodology", stdout)

        service = AdjudicationSealService(
            error=self.cli.CohortEvidenceSealError,
            parse_timestamp=self.cli.parse_timestamp,
            hash_value=sha256_value,
            validate_embedded_digest=self.cli.validate_embedded_digest,
        )
        self.assertEqual(
            service.validate_evidence_seal(seal, expected_count=2)["seal_sha256"],
            seal["seal_sha256"],
        )

    def test_refuses_overwrite_tamper_and_non_private_inputs(self) -> None:
        self.assertEqual(self._run()[0], 0)
        original = self.output_path.read_bytes()
        self.assertEqual(self._run()[0], 2)
        self.assertEqual(self.output_path.read_bytes(), original)

        self.output_path.unlink()
        draft = self._draft()
        draft["reviewer_count"] = 2
        self._write_json(self.draft_path, draft)
        self.assertEqual(self._run()[0], 2)

        self._write_json(self.draft_path, self._draft())
        self.methodology_path.chmod(0o644)
        self.assertEqual(self._run()[0], 2)

    def test_rejects_dispatched_or_mismatched_role_manifests(self) -> None:
        self.manifests["soc-analyst"]["state"] = "queued"
        self._resign_manifest("soc-analyst", self.soc_path)
        self.assertEqual(self._run()[0], 2)

        self.manifests["soc-analyst"] = self._manifest("soc-analyst")
        self.manifests["soc-analyst"]["members"][0]["detection"][
            "rule_name"
        ] = "different-rule"
        self._resign_manifest("soc-analyst", self.soc_path)
        self.assertEqual(self._run()[0], 2)


if __name__ == "__main__":
    unittest.main()
