from __future__ import annotations

import datetime as dt
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD_DIR))

import cti_program  # noqa: E402
import cti_program_lifecycle  # noqa: E402


def lifecycle_payload() -> dict[str, object]:
    base = cti_program.load_program(Path("/path/that/does/not/exist"))
    source = dict(base["sources"][0])
    source.update(
        {
            "collection_status": "failed",
            "last_attempt_at": "2026-08-14T12:00:00Z",
            "last_success_at": "2026-08-13T12:00:00Z",
            "failure_code": "upstream-timeout",
        }
    )
    requirement = {
        "id": "pir-exposure",
        "active": True,
        "title": "Exploited vulnerability exposure",
        "decision": "Patch, mitigate, detect, or accept risk",
        "sponsor": "Security Operations",
        "consumers": ["Platform Operations", "Detection Engineering"],
        "priority": "critical",
        "horizon": "30 days",
        "cadence": "daily",
        "collection_gaps": ["Exact affected asset versions"],
        "deliverable": "Prioritized exposure brief",
        "success_criteria": "Every applicable exposure has an owned decision",
        "review_date": "2026-09-01",
        "status": "active",
    }
    intelligence = {
        "id": "intel-kev-2026-001",
        "deduplication_key": "cisa-kev:cve-2026-0001",
        "title": "CVE-2026-0001 added to KEV",
        "lifecycle_state": "evaluation",
        "requirement_ids": ["pir-exposure"],
        "source_ids": [source["id"]],
        "affected_technology_ids": [base["technologies"][0]["id"]],
        "source_reliability": "A",
        "information_credibility": "2",
        "confidence": "high",
        "handling": "TLP:CLEAR",
        "collected_at": "2026-08-13T10:00:00Z",
        "analyzed_at": "2026-08-13T11:00:00Z",
        "published_at": "2026-08-13T12:00:00Z",
        "expires_at": "2026-08-14T12:00:00Z",
        "summary": "Authoritative exploitation reporting requires local validation.",
        "analytic_judgment": "Potentially relevant; applicability remains unproven.",
        "assumptions": ["The vendor mapping is current"],
        "alternatives": ["The deployed version may not be affected"],
        "evidence": [
            {
                "id": "evidence-kev-entry",
                "kind": "source-record",
                "reference": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "description": "Catalog record metadata; raw source content is not stored.",
                "observed_at": "2026-08-13T10:00:00Z",
                "source_id": source["id"],
                "handling": "TLP:CLEAR",
            }
        ],
        "entities": [
            {
                "id": "entity-cve-2026-0001",
                "entity_type": "vulnerability",
                "value": "CVE-2026-0001",
                "evidence_ids": ["evidence-kev-entry"],
                "affected_technology_ids": [base["technologies"][0]["id"]],
            },
            {
                "id": "action-validate-exposure",
                "entity_type": "defensive-action",
                "value": "Validate deployed version and exposure",
                "evidence_ids": ["evidence-kev-entry"],
                "affected_technology_ids": [base["technologies"][0]["id"]],
            },
        ],
        "investigation_use": "context-only",
    }
    return {
        "sources": [source],
        "technologies": [base["technologies"][0]],
        "requirements": [requirement],
        "intelligence": [intelligence],
    }


class CTILifecycleContractTests(unittest.TestCase):
    def test_defaults_represent_every_lifecycle_collection_and_fixed_authority(self):
        program = cti_program.load_program(Path("/path/that/does/not/exist"))
        self.assertEqual(program["requirements"], [])
        self.assertEqual(program["intelligence"], [])
        self.assertEqual(program["audit_history"], [])
        response = cti_program.public_response(program)
        self.assertEqual(
            response["lifecycle"]["states"],
            [
                "requirements",
                "collection",
                "processing",
                "analysis",
                "dissemination",
                "feedback",
                "evaluation",
            ],
        )
        self.assertEqual(response["investigation_policy"]["authority"], "context-only")
        self.assertFalse(response["investigation_policy"]["may_assert_fact"])
        self.assertFalse(response["investigation_policy"]["may_set_detection_outcome"])

    def test_full_lifecycle_metadata_and_evidence_links_round_trip(self):
        normalized = cti_program.normalize_program(lifecycle_payload())
        source = normalized["sources"][0]
        item = normalized["intelligence"][0]
        self.assertEqual(source["collection_status"], "failed")
        self.assertEqual(source["failure_code"], "upstream-timeout")
        self.assertEqual(item["source_reliability"], "A")
        self.assertEqual(item["information_credibility"], "2")
        self.assertEqual(item["confidence"], "high")
        self.assertEqual(item["handling"], "TLP:CLEAR")
        self.assertEqual(item["investigation_use"], "context-only")
        self.assertEqual(
            {entity["entity_type"] for entity in item["entities"]},
            {"vulnerability", "defensive-action"},
        )
        self.assertEqual(item["entities"][0]["evidence_ids"], ["evidence-kev-entry"])

    def test_new_requirement_and_intelligence_ids_are_generated_once_on_admission(self):
        payload = lifecycle_payload()
        payload["requirements"][0]["id"] = ""
        payload["intelligence"][0]["id"] = ""
        payload["intelligence"][0]["requirement_ids"] = []
        normalized = cti_program.normalize_program(payload)
        self.assertRegex(normalized["requirements"][0]["id"], r"^[a-f0-9]{32}$")
        self.assertRegex(normalized["intelligence"][0]["id"], r"^[a-f0-9]{32}$")

    def test_expired_intelligence_is_projected_as_stale_without_rewriting_evidence(self):
        item = cti_program.normalize_program(lifecycle_payload())["intelligence"][0]
        status = cti_program_lifecycle.intelligence_freshness(
            item,
            now=dt.datetime(2026, 8, 14, 12, 0, 1, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(status, "stale")
        self.assertEqual(item["expires_at"], "2026-08-14T12:00:00Z")

    def test_investigation_projection_is_context_only_and_evidence_linked(self):
        program = cti_program.normalize_program(lifecycle_payload())
        context = cti_program_lifecycle.project_investigation_context(
            program,
            ["intel-kev-2026-001"],
            now=dt.datetime(2026, 8, 14, 12, 0, 1, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(context["authority"], "context-only")
        self.assertFalse(context["may_assert_fact"])
        self.assertFalse(context["may_set_detection_outcome"])
        self.assertTrue(context["requires_independent_evidence"])
        self.assertEqual(context["items"][0]["freshness"], "stale")
        self.assertEqual(
            context["items"][0]["evidence"][0]["id"], "evidence-kev-entry"
        )
        with self.assertRaisesRegex(cti_program.CTIProgramError, "Unknown intelligence"):
            cti_program_lifecycle.project_investigation_context(
                program, ["missing-intelligence"]
            )

    def test_duplicates_are_rejected_across_requirements_intelligence_and_evidence(self):
        payload = lifecycle_payload()
        payload["requirements"] = [payload["requirements"][0]] * 2
        with self.assertRaisesRegex(cti_program.CTIProgramError, "Requirement ids"):
            cti_program.normalize_program(payload)

        payload = lifecycle_payload()
        duplicate = dict(payload["intelligence"][0])
        duplicate["id"] = "intel-kev-2026-002"
        payload["intelligence"] = [payload["intelligence"][0], duplicate]
        with self.assertRaisesRegex(cti_program.CTIProgramError, "deduplication keys"):
            cti_program.normalize_program(payload)

        payload = lifecycle_payload()
        evidence = payload["intelligence"][0]["evidence"][0]
        payload["intelligence"][0]["evidence"] = [evidence, dict(evidence)]
        with self.assertRaisesRegex(cti_program.CTIProgramError, "Evidence ids"):
            cti_program.normalize_program(payload)

    def test_dangling_source_requirement_technology_and_evidence_links_fail_closed(self):
        replacements = (
            ("source_ids", ["missing-source"], "unknown source"),
            ("requirement_ids", ["missing-requirement"], "unknown requirement"),
            ("affected_technology_ids", ["missing-technology"], "unknown technology"),
        )
        for field, value, message in replacements:
            payload = lifecycle_payload()
            payload["intelligence"][0][field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(cti_program.CTIProgramError, message):
                    cti_program.normalize_program(payload)
        payload = lifecycle_payload()
        payload["intelligence"][0]["entities"][0]["evidence_ids"] = ["missing-evidence"]
        with self.assertRaisesRegex(cti_program.CTIProgramError, "unknown evidence"):
            cti_program.normalize_program(payload)

    def test_intelligence_cannot_claim_fact_or_detection_authority(self):
        for field, value in (
            ("investigation_use", "fact"),
            ("detection_outcome", "malicious"),
        ):
            payload = lifecycle_payload()
            payload["intelligence"][0][field] = value
            with self.subTest(field=field):
                with self.assertRaises(cti_program.CTIProgramError):
                    cti_program.normalize_program(payload)

    def test_temporal_handling_and_evidence_relationships_fail_closed(self):
        payload = lifecycle_payload()
        payload["intelligence"][0]["analyzed_at"] = "2026-08-13T09:00:00Z"
        with self.assertRaisesRegex(cti_program.CTIProgramError, "cannot precede"):
            cti_program.normalize_program(payload)

        payload = lifecycle_payload()
        payload["intelligence"][0]["handling"] = "TLP:CLEAR"
        payload["intelligence"][0]["evidence"][0]["handling"] = "TLP:RED"
        with self.assertRaisesRegex(cti_program.CTIProgramError, "less restrictive"):
            cti_program.normalize_program(payload)

        payload = lifecycle_payload()
        payload["intelligence"][0]["source_ids"] = []
        with self.assertRaisesRegex(cti_program.CTIProgramError, "not linked by source_ids"):
            cti_program.normalize_program(payload)

        payload = lifecycle_payload()
        payload["intelligence"][0]["entities"][0]["evidence_ids"] = []
        with self.assertRaisesRegex(cti_program.CTIProgramError, "must link admitted evidence"):
            cti_program.normalize_program(payload)

    def test_source_failure_code_cannot_store_secret_bearing_diagnostics(self):
        payload = lifecycle_payload()
        payload["sources"][0]["failure_code"] = "Bearer super-secret-token"
        with self.assertRaisesRegex(cti_program.CTIProgramError, "redacted lowercase"):
            cti_program.normalize_program(payload)

    def test_source_collection_failure_and_success_states_are_coherent(self):
        payload = lifecycle_payload()
        payload["sources"][0]["failure_code"] = ""
        with self.assertRaisesRegex(cti_program.CTIProgramError, "requires last_attempt"):
            cti_program.normalize_program(payload)

        payload = lifecycle_payload()
        payload["sources"][0]["last_success_at"] = "2026-08-15T12:00:00Z"
        with self.assertRaisesRegex(cti_program.CTIProgramError, "cannot follow"):
            cti_program.normalize_program(payload)

        payload = lifecycle_payload()
        payload["sources"][0].update(
            {
                "collection_status": "healthy",
                "last_attempt_at": "2026-08-14T12:00:00Z",
                "last_success_at": "",
                "failure_code": "",
            }
        )
        with self.assertRaisesRegex(cti_program.CTIProgramError, "requires last_success"):
            cti_program.normalize_program(payload)

    def test_revisioned_save_preserves_lifecycle_and_records_metadata_only_edit_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cti.json"
            payload = lifecycle_payload()
            saved = cti_program.save_program(
                {"expected_revision": 0, **payload},
                path,
            )
            self.assertEqual(saved["revision"], 1)
            self.assertEqual(len(saved["requirements"]), 1)
            self.assertEqual(len(saved["intelligence"]), 1)
            self.assertEqual(len(saved["audit_history"]), 1)
            event = saved["audit_history"][0]
            self.assertEqual(event["revision"], 1)
            self.assertEqual(event["event"], "workspace-updated")
            self.assertIn("requirements:pir-exposure:added", event["changes"])
            self.assertIn("intelligence:intel-kev-2026-001:added", event["changes"])
            serialized = json.dumps(event)
            self.assertNotIn("CVE-2026-0001 added to KEV", serialized)
            self.assertEqual(cti_program.load_program(path), saved)

    def test_legacy_source_only_save_preserves_existing_lifecycle_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cti.json"
            initial = cti_program.save_program(
                {"expected_revision": 0, **lifecycle_payload()}, path
            )
            saved = cti_program.save_program(
                {
                    "expected_revision": 1,
                    "sources": initial["sources"],
                    "technologies": initial["technologies"],
                },
                path,
            )
            self.assertEqual(saved["requirements"], initial["requirements"])
            self.assertEqual(saved["intelligence"], initial["intelligence"])

    def test_legacy_stored_workspace_is_migrated_in_memory_without_rewrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cti.json"
            legacy = cti_program.load_program(Path("/path/that/does/not/exist"))
            for field in ("requirements", "intelligence", "audit_history"):
                legacy.pop(field)
            for source in legacy["sources"]:
                for field in (
                    "collection_status",
                    "last_attempt_at",
                    "last_success_at",
                    "failure_code",
                ):
                    source.pop(field)
            path.write_text(json.dumps(legacy), encoding="utf-8")
            original = path.read_bytes()
            loaded = cti_program.load_program(path)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(loaded["requirements"], [])
            self.assertEqual(loaded["intelligence"], [])
            self.assertEqual(loaded["audit_history"], [])
            self.assertEqual(loaded["sources"][0]["collection_status"], "unknown")

    def test_audit_history_is_bounded_to_latest_one_hundred_revisions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cti.json"
            payload = lifecycle_payload()
            saved = cti_program.save_program(
                {"expected_revision": 0, **payload}, path
            )
            for revision in range(1, 105):
                saved = cti_program.save_program(
                    {
                        "expected_revision": revision,
                        "sources": saved["sources"],
                        "technologies": saved["technologies"],
                    },
                    path,
                )
            self.assertEqual(saved["revision"], 105)
            self.assertEqual(len(saved["audit_history"]), 100)
            self.assertEqual(saved["audit_history"][0]["revision"], 6)
            self.assertEqual(saved["audit_history"][-1]["revision"], 105)


if __name__ == "__main__":
    unittest.main()
